# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The BACKLOG #1292 intake audit -- the per-message discriminator for an ``engine_read`` shortfall.

THE DEFECT UNDER TEST is an ATTRIBUTION defect, not a counting one. ``connscale``'s no-loss reconcile
fails with ``engine_read {read} < confirmed sent {sent - excused} (lost N on intake)``, and that
sentence is produced identically by an engine that lost an acknowledged message and by a harness
gauge that was sampled early or summed short. So the assertions here are about which VERDICT a given
world produces, and the decisive test is that three worlds which are indistinguishable to the count
check produce three DIFFERENT verdicts here.

The three planted worlds mirror the three ways this can go, and they are deliberately not variations
of one:

* the rows ARE all there, a shortfall is reported, and
  part of it survives setting the never-confirmed
  sends aside                                          -> SAMPLING_LAG      (harness/instrument)
* an ACCEPT-ACKed row is genuinely absent               -> INVARIANT_SUSPECT (the engine branch)
* the probe's own read comes back empty                 -> PROBE_UNUSABLE    (the null guard)

The third is not optional. Without it a broken query renders as "every message is missing", which is
the worst possible false positive to hang a P1 on -- a catastrophic-looking engine finding produced
entirely by the instrument.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from harness.load.connscale.intake_audit import (
    MOMENT_LIVE,
    MOMENT_POST_MORTEM,
    VERDICT_CORRELATION_SUSPECT,
    VERDICT_INTAKE_COMPLETE,
    VERDICT_INVARIANT_SUSPECT,
    VERDICT_NOT_RUN,
    VERDICT_PROBE_UNUSABLE,
    VERDICT_SAMPLING_LAG,
    VERDICT_UNCONFIRMED_SHORTFALL,
    IntakeAudit,
    IntakeLedger,
    StoreSnapshot,
    judge,
    not_run,
    run_intake_audit,
    sweep_store,
)
from harness.load.connscale.profile import load_connscale_profile_text
from harness.load.connscale.report import ConnScaleRecord, SloCheck
from harness.load.connscale.runner import (
    _build_record,
    _evaluate_slos,
    _read_shortfall,
    _reconcile,
)
from harness.load.enginepoll import EnginePoller, EngineSample
from harness.load.metrics import Counters, Histogram
from messagefoundry.store.store import MessageStore


def _ledger(*, accepted: int = 3, rejected: int = 0, unconfirmed: int = 0) -> IntakeLedger:
    """A ledger shaped like one real step: ``accepted`` AA sends, ``rejected`` AE sends, and
    ``unconfirmed`` sends stranded at a connection close."""
    led = IntakeLedger()
    seq = 0
    for _ in range(accepted):
        led.record_confirmed(f"CID{seq:04d}", seq, "AA", accepted=True)
        seq += 1
    for _ in range(rejected):
        led.record_confirmed(f"CID{seq:04d}", seq, "AE", accepted=False)
        seq += 1
    for _ in range(unconfirmed):
        led.record_unconfirmed(f"CID{seq:04d}", seq)
        seq += 1
    return led


def _all_ids(led: IntakeLedger) -> frozenset[str]:
    return frozenset({*led.confirmed, *led.unconfirmed})


# --- PLANT A: the rows are all there, yet the count check reported a shortfall -------------------


def test_plant_a_full_store_with_shortfall_is_sampling_lag() -> None:
    led = _ledger(accepted=5)
    snap = StoreSnapshot(_all_ids(led), total=5)

    audit = judge(led, snap, moment=MOMENT_POST_MORTEM, sent=5, read_short=2)

    assert audit.verdict == VERDICT_SAMPLING_LAG
    # Nothing is claimed lost -- the whole point is that the shortfall is in the gauge.
    assert audit.missing_accepted_total == 0
    assert audit.read_short == 2 and audit.store_total == 5
    assert "engine_read gauge" in audit.detail
    assert not audit.engine_suspect and audit.conclusive


# --- PLANT B: an accept-ACKed message is genuinely absent ---------------------------------------


def test_plant_b_absent_accepted_message_is_invariant_suspect_and_names_it() -> None:
    led = _ledger(accepted=5)
    present = frozenset(cid for cid in led.confirmed if cid != "CID0002")
    snap = StoreSnapshot(present, total=4)

    audit = judge(led, snap, moment=MOMENT_POST_MORTEM, sent=5, read_short=1)

    assert audit.verdict == VERDICT_INVARIANT_SUSPECT
    assert audit.engine_suspect
    assert audit.missing_accepted_total == 1
    # NAMED, so the finding is reproducible rather than statistical -- by SEQUENCE NUMBER, because
    # the artifact rule for this family forbids control-id lists.
    assert audit.missing_accepted_seqs == (2,)
    assert audit.missing_codes == ("AA",)
    assert "count-and-log invariant" in audit.detail


def test_plant_b_verdict_differs_from_plant_a_on_the_same_shortfall() -> None:
    """THE ITEM, in one assertion: two worlds the count check cannot tell apart.

    Both have ``sent=5`` and a reported shortfall, so both produce the SAME
    ``engine_read ... < confirmed sent ...`` message today. The audit separates them, and separates
    them into the two branches that have opposite owners.
    """
    led = _ledger(accepted=5)
    lag = judge(
        led, StoreSnapshot(_all_ids(led), 5), moment=MOMENT_POST_MORTEM, sent=5, read_short=1
    )
    loss = judge(
        led,
        StoreSnapshot(frozenset(c for c in led.confirmed if c != "CID0000"), 4),
        moment=MOMENT_POST_MORTEM,
        sent=5,
        read_short=1,
    )
    assert lag.read_short == loss.read_short == 1  # identical to the count check
    assert lag.verdict != loss.verdict
    assert (lag.engine_suspect, loss.engine_suspect) == (False, True)


# --- PLANT C: the probe itself read nothing ------------------------------------------------------


def test_plant_c_empty_store_read_is_unusable_not_total_loss() -> None:
    """A NULL NEEDS A MECHANISM. An empty read is what a broken query returns, and it is also what an
    empty store returns; the two warrant opposite verdicts, so the empty read is refused rather than
    rendered as the catastrophic reading."""
    led = _ledger(accepted=5)
    snap = StoreSnapshot(frozenset(), total=0)

    audit = judge(led, snap, moment=MOMENT_POST_MORTEM, sent=5, read_short=5)

    assert audit.verdict == VERDICT_PROBE_UNUSABLE
    assert not audit.engine_suspect
    # The decisive assertion: it did NOT report five lost messages.
    assert audit.missing_accepted_total == 0
    assert "NOT as 5 lost messages" in audit.detail


def test_the_three_plants_yield_three_distinct_verdicts() -> None:
    """Two plants that agree are not two directions. Enumerated, so a future edit that collapses two
    of these paths into one fails here rather than quietly halving the instrument."""
    led = _ledger(accepted=4)
    verdicts = {
        judge(
            led, StoreSnapshot(_all_ids(led), 4), moment=MOMENT_POST_MORTEM, sent=4, read_short=1
        ).verdict,
        judge(
            led,
            StoreSnapshot(frozenset(list(led.confirmed)[1:]), 3),
            moment=MOMENT_POST_MORTEM,
            sent=4,
            read_short=1,
        ).verdict,
        judge(
            led, StoreSnapshot(frozenset(), 0), moment=MOMENT_POST_MORTEM, sent=4, read_short=1
        ).verdict,
    }
    assert verdicts == {VERDICT_SAMPLING_LAG, VERDICT_INVARIANT_SUSPECT, VERDICT_PROBE_UNUSABLE}


# --- the fourth outcome: a rejected send is not an engine finding --------------------------------


def test_absent_rejected_message_is_correlation_suspect_not_loss() -> None:
    """Several NAK limbs record their ``messages`` row with a NULL control id (they run before an
    MSH-10 has been parsed), so a rejected send is EXPECTED to be unmatchable by control id. Reading
    that as intake loss would manufacture a P1 out of correct engine behaviour."""
    led = _ledger(accepted=3, rejected=1)
    present = frozenset(cid for cid, rec in led.confirmed.items() if rec.accepted)
    snap = StoreSnapshot(present, total=3)

    audit = judge(led, snap, moment=MOMENT_POST_MORTEM, sent=4, read_short=1)

    assert audit.verdict == VERDICT_CORRELATION_SUSPECT
    assert not audit.engine_suspect
    assert audit.missing_rejected_total == 1 and audit.missing_accepted_total == 0
    assert audit.missing_codes == ("AE",)


def test_a_rejected_send_that_IS_stored_is_not_a_correlation_finding() -> None:
    """The negative control for the branch above, and it is the one that pins the MEMBERSHIP test.

    The NULL-control-id NAK limbs are only SOME of them: a limb that rejects AFTER parsing MSH-10
    writes a row that DOES carry the id, and the sweep finds it. Without this, dropping the
    ``cid not in store_ids`` half of the predicate -- leaving a bare ``not rec.accepted`` -- kept the
    whole suite green while turning every ordinary NAK into a standing CORRELATION_SUSPECT that
    ``report.py`` prints on each clean step, and which the smoke assertion cannot catch because that
    verdict is conclusive and not engine_suspect. This is the false-alarm direction.
    """
    led = _ledger(accepted=3, rejected=1)
    audit = judge(
        led, StoreSnapshot(_all_ids(led), total=4), moment=MOMENT_POST_MORTEM, sent=4, read_short=0
    )

    assert audit.verdict == VERDICT_INTAKE_COMPLETE
    assert audit.missing_rejected_total == 0 and audit.missing_accepted_total == 0


# --- the LEDGER-side positive control, and the shortfall it must not misattribute ----------------


def test_a_ledger_with_nothing_confirmed_is_unusable_not_clean() -> None:
    """THE BLIND-BUT-GREEN CASE, and the one the store-side control could not see.

    ``confirmed`` is the only set compared; ``unconfirmed`` is read as a count and never searched.
    So a step where no send was ever ACKed compares an EMPTY set, and every guard keyed on
    ``ledger.total`` -- which counts both -- waves it through. It is reachable on the harness's own
    headline fault: the runner's excusal clamps ``excused`` to 0 once the unconfirmed count exceeds
    its budget, so such a step arrives here with a large ``read_short``.

    Before the ledger-side control this returned a CONCLUSIVE verdict stating the shortfall was
    "not in intake" -- computed over zero elements, rendering a green SLO row, and passing all four
    smoke assertions -- on precisely the step the reconcile calls a possible accepted-and-dropped.
    """
    led = _ledger(accepted=0, unconfirmed=5)
    snap = StoreSnapshot(frozenset({"OTHER0", "OTHER1", "OTHER2"}), total=3)

    audit = judge(led, snap, moment=MOMENT_POST_MORTEM, sent=5, read_short=2)

    assert audit.verdict == VERDICT_PROBE_UNUSABLE
    assert "NO send was ever confirmed" in audit.detail
    # The properties that actually protect the run: an empty comparison must not be readable as an
    # answer, and must never clear the engine.
    assert not audit.conclusive
    assert not audit.engine_suspect


def test_a_shortfall_inside_the_unconfirmed_set_does_not_accuse_the_gauge() -> None:
    """A shortfall made ENTIRELY of never-confirmed sends implicates neither intake nor the gauge.

    ``_excusal`` clamps ``excused`` to 0 when the unconfirmed count exceeds its budget, so
    ``read_short`` then carries sends the engine may never have received. Calling that SAMPLING_LAG
    accused an ``engine_read`` gauge that matched the store exactly, and the sentence was appended
    verbatim to the reconcile's own "systemic no-ACK fault" line -- one failure message contradicting
    itself and pointing at an enginepoll bug that does not exist.
    """
    led = _ledger(accepted=2, unconfirmed=8)
    stored = frozenset(led.confirmed)
    # The OVER-BUDGET world: excusal clamped to 0, so read_short = sent - read = 8, and once the 8
    # never-confirmed sends are set aside nothing is unexplained (10 - 8 - 2 = 0).
    audit = judge(
        led,
        StoreSnapshot(stored, total=2),
        moment=MOMENT_POST_MORTEM,
        sent=10,
        read_short=8,
        unexplained_short=0,
    )

    assert audit.verdict == VERDICT_UNCONFIRMED_SHORTFALL
    assert audit.conclusive and not audit.engine_suspect
    # The regression guard keys on the ACCUSATION, not on the words "engine_read gauge" -- this
    # detail names the gauge inside a NEGATION ("implicates NEITHER intake NOR the engine_read
    # gauge"), so a bare substring test would answer a different question than the one asked.
    # "sample attribution" is the diagnosis unique to SAMPLING_LAG, and is what must be absent.
    assert "sample attribution" not in audit.detail
    assert "never-confirmed" in audit.detail


def test_a_shortfall_larger_than_the_unconfirmed_set_still_names_the_gauge() -> None:
    """The complement, so the split above cannot be satisfied by never returning SAMPLING_LAG.

    One more missing than the never-confirmed sends can account for, with every confirmed send
    present, leaves a remainder nothing else explains -- and THAT is a real gauge finding.
    """
    led = _ledger(accepted=2, unconfirmed=8)
    audit = judge(
        led,
        StoreSnapshot(frozenset(led.confirmed), total=2),
        moment=MOMENT_POST_MORTEM,
        sent=10,
        read_short=9,
        unexplained_short=1,
    )

    assert audit.verdict == VERDICT_SAMPLING_LAG
    assert "sample attribution" in audit.detail


def test_an_IN_BUDGET_shortfall_is_a_gauge_finding_even_though_sends_went_unconfirmed() -> None:
    """THE REGRESSION THAT AN INFERRED PREDICATE GETS BACKWARDS, and it is the COMMON path.

    A first cut at the split above asked ``read_short <= len(ledger.unconfirmed)`` and read a True as
    "the excusal was clamped". That inference only holds OVER budget. In budget ``excused ==
    unconfirmed``, so the never-confirmed sends are ALREADY subtracted out of ``read_short`` and any
    residue is confirmed sends the gauge did not count -- a genuine SAMPLING_LAG. Because
    over-budget needs ``timeouts > 3/4 sent``, the in-budget world here is the ordinary one, so the
    inferred predicate silenced a real gauge finding on the path most runs take.

    Numbers are the real arithmetic: sent=100, timeouts=5, engine_read=93. ``_excusal`` is in budget
    (5 <= max(24, 75)) so ``excused``=5 and ``read_short`` = 100-5-93 = 2, while the unconfirmed
    count is 5 -- and 2 <= 5, which is exactly the shape the bad predicate accepted. The producer's
    ``unexplained`` = 100-5-93 = 2 is positive, so the gauge is correctly named.
    """
    led = _ledger(accepted=95, unconfirmed=5)
    audit = judge(
        led,
        StoreSnapshot(frozenset(led.confirmed), total=95),
        moment=MOMENT_POST_MORTEM,
        sent=100,
        read_short=2,
        unexplained_short=2,
    )

    assert audit.verdict == VERDICT_SAMPLING_LAG
    assert "sample attribution" in audit.detail


def test_the_unexplained_remainder_comes_from_the_producer_not_the_ledger() -> None:
    """The two worlds are INDISTINGUISHABLE from inside judge(), which is why it must not guess.

    Identical ledger, identical store, identical ``read_short`` -- only the producer's
    ``unexplained_short`` differs, and the verdict flips. That is the whole argument for passing it:
    no function of the ledger alone could separate these two.
    """

    def _verdict(unexplained: int) -> str:
        led = _ledger(accepted=2, unconfirmed=8)
        return judge(
            led,
            StoreSnapshot(frozenset(led.confirmed), total=2),
            moment=MOMENT_POST_MORTEM,
            sent=10,
            read_short=8,
            unexplained_short=unexplained,
        ).verdict

    assert _verdict(0) == VERDICT_UNCONFIRMED_SHORTFALL
    assert _verdict(3) == VERDICT_SAMPLING_LAG


def test_only_the_post_mortem_moment_states_the_engine_conclusion() -> None:
    """The same absent row concludes DIFFERENT things at the two moments, and the text must say so.

    ``sweep_store`` pages ``ORDER BY received_at DESC`` + OFFSET, so a row committed while a LIVE
    sweep walks shifts the window and a genuinely present row can go unread -- documented as known
    and deliberate, and it manufactures exactly this verdict. The machine gates already read only the
    post-mortem, but the live detail is printed to the console and stored in the JSON artifact, where
    an unhedged "the count-and-log invariant would not hold" is quotable as an engine finding that
    the post-mortem beside it may not support.
    """
    led = _ledger(accepted=3)
    snap = StoreSnapshot(frozenset(list(led.confirmed)[1:]), total=2)

    live = judge(led, snap, moment=MOMENT_LIVE, sent=3, read_short=1)
    post = judge(led, snap, moment=MOMENT_POST_MORTEM, sent=3, read_short=1)

    # Both SEE it -- the hedge must not suppress the finding, only its conclusion.
    assert live.verdict == post.verdict == VERDICT_INVARIANT_SUSPECT
    assert live.missing_accepted_total == post.missing_accepted_total == 1

    assert "count-and-log invariant would not hold" in post.detail
    assert "STOPPED" in post.detail
    assert "count-and-log invariant would not hold" not in live.detail
    assert "post-mortem reproduces it" in live.detail

    # The MACHINE surface must agree with the prose by construction, not because the SLO gate
    # happens to read the post-mortem field. A live sweep can manufacture this verdict; only the
    # post-mortem may carry it into `engine_suspect`, which is what fails the run.
    assert post.engine_suspect and not live.engine_suspect


# --- the positive controls ------------------------------------------------------------------------


def test_clean_run_reports_late_unconfirmed_as_its_positive_control() -> None:
    """``late_unconfirmed`` proves the sweep sees BEYOND the confirmed set: an excused send that
    nevertheless arrived. A sweep that only ever returned the confirmed ids would score clean here
    and would be blind to exactly the messages the reconcile forgives."""
    led = _ledger(accepted=3, unconfirmed=1)
    snap = StoreSnapshot(_all_ids(led), total=4)

    audit = judge(led, snap, moment=MOMENT_POST_MORTEM, sent=4, read_short=0)

    assert audit.verdict == VERDICT_INTAKE_COMPLETE
    assert audit.late_unconfirmed_total == 1
    assert audit.unconfirmed_total == 1 and audit.confirmed_total == 3
    assert audit.store_total == 4


def test_empty_ledger_against_real_sends_is_unusable() -> None:
    """The sender-side positive control. An audit over a ledger that recorded nothing is vacuously
    clean, so it is refused."""
    audit = judge(
        IntakeLedger(), StoreSnapshot(frozenset(), 0), moment=MOMENT_LIVE, sent=7, read_short=1
    )
    assert audit.verdict == VERDICT_PROBE_UNUSABLE
    assert "recorded NOTHING against 7" in audit.detail


def test_zero_send_step_is_complete_not_unusable() -> None:
    """A step that sent nothing has nothing to audit and is not an instrument failure."""
    audit = judge(
        IntakeLedger(), StoreSnapshot(frozenset(), 0), moment=MOMENT_LIVE, sent=0, read_short=0
    )
    assert audit.verdict == VERDICT_INTAKE_COMPLETE


# --- the partial-ledger split: a positive finding survives it, a null does not --------------------


def test_partial_ledger_makes_a_NULL_unusable() -> None:
    led = _ledger(accepted=3)
    snap = StoreSnapshot(_all_ids(led), total=3)
    audit = judge(led, snap, moment=MOMENT_POST_MORTEM, sent=5, read_short=0)
    assert audit.verdict == VERDICT_PROBE_UNUSABLE
    assert "accounted 3 of 5" in audit.detail


def test_partial_ledger_does_not_suppress_a_POSITIVE_finding() -> None:
    """The mirror image, and the reason the two guards sit on opposite sides of the finding checks: a
    short ledger under-reports, so a message inside it that is genuinely absent is still absent."""
    led = _ledger(accepted=3)
    snap = StoreSnapshot(frozenset(list(led.confirmed)[1:]), total=2)
    audit = judge(led, snap, moment=MOMENT_POST_MORTEM, sent=5, read_short=3)
    assert audit.verdict == VERDICT_INVARIANT_SUSPECT
    assert "LOWER BOUND" in audit.detail


def test_ledger_overflow_and_duplicates_are_unusable() -> None:
    small = IntakeLedger(capacity=2)
    for i in range(4):
        small.record_confirmed(f"C{i}", i, "AA", accepted=True)
    assert small.overflow == 2
    # The snapshot trips NO OTHER GUARD -- rows present, nothing truncated, no error, and every id
    # the ledger did manage to record IS in the store -- and the DETAIL is asserted, not just the
    # verdict. Both matter: with the overflow guard deleted this world still reaches
    # PROBE_UNUSABLE via the partial-ledger guard ("accounted 2 of 4"), so a verdict-only assertion
    # passed with the guard under test entirely removed. Overflow is step 1 of the blindness
    # ordering, and a step whose test cannot fail is not covering it.
    snap = StoreSnapshot(frozenset(small.confirmed), total=len(small.confirmed))
    overflowed = judge(small, snap, moment=MOMENT_LIVE, sent=4, read_short=0)
    assert overflowed.verdict == VERDICT_PROBE_UNUSABLE
    assert "overflowed" in overflowed.detail

    dup = IntakeLedger()
    dup.record_confirmed("SAME", 0, "AA", accepted=True)
    dup.record_confirmed("SAME", 1, "AA", accepted=True)
    assert dup.duplicates == 1
    audit = judge(
        dup, StoreSnapshot(frozenset({"SAME"}), 1), moment=MOMENT_LIVE, sent=2, read_short=0
    )
    assert audit.verdict == VERDICT_PROBE_UNUSABLE
    assert "duplicate control id" in audit.detail


def test_not_run_is_neither_a_pass_nor_a_finding() -> None:
    audit = not_run("audit disabled")
    assert audit.verdict == VERDICT_NOT_RUN
    assert not audit.conclusive and not audit.engine_suspect


# --- run_intake_audit: a broken reader is a probe outcome, never a run failure --------------------


def test_reader_exception_becomes_probe_unusable() -> None:
    led = _ledger(accepted=2)

    async def _boom() -> StoreSnapshot:
        raise RuntimeError("no such table: messages")

    audit = asyncio.run(
        run_intake_audit(led, _boom, moment=MOMENT_POST_MORTEM, sent=2, read_short=2)
    )
    assert audit.verdict == VERDICT_PROBE_UNUSABLE
    assert "RuntimeError" in audit.detail and "no such table" in audit.detail
    assert audit.missing_accepted_total == 0


# --- the REAL store sweep, against a real SQLite store -------------------------------------------


def test_sweep_reads_control_ids_from_a_real_store(tmp_path: Path) -> None:
    """RUN THE THING: the reader against a real ``MessageStore``, not a stub.

    Includes its own positive control -- a control id that was never inserted must NOT come back --
    because a sweep that returned everything asked of it would pass a membership test without ever
    querying anything.
    """

    async def go() -> None:
        store = await MessageStore.open(tmp_path / "sweep.db")
        try:
            for i in range(3):
                await store.enqueue_ingress(
                    channel_id="IB_CS_00000",
                    raw=f"MSH|^~\\&|A|B|C|D|20260101||ADT^A01|SWEEP{i:04d}|P|2.5\r",
                    control_id=f"SWEEP{i:04d}",
                    message_type="ADT^A01",
                )
            snap = await sweep_store(store, row_cap=1000)
            assert snap.total == 3 and not snap.truncated and snap.error is None
            assert snap.control_ids == {"SWEEP0000", "SWEEP0001", "SWEEP0002"}
            assert "SWEEP9999" not in snap.control_ids  # the sweep discriminates, it does not echo

            # And the cap: a table bigger than the cap is TRUNCATED, never a short set that would
            # read as absence for every row the sweep did not reach.
            capped = await sweep_store(store, row_cap=2)
            assert capped.truncated and capped.total == 3 and capped.control_ids == frozenset()
            assert (
                judge(
                    _ledger(accepted=3), capped, moment=MOMENT_POST_MORTEM, sent=3, read_short=1
                ).verdict
                == VERDICT_PROBE_UNUSABLE
            )
        finally:
            await store.close()

    asyncio.run(go())


def test_sweep_of_an_empty_real_store_is_refused_by_judge(tmp_path: Path) -> None:
    """The end-to-end null guard: a REAL sweep of a REAL empty store returns the same empty set a
    broken query would, and ``judge`` refuses it rather than reporting total loss."""

    async def go() -> None:
        store = await MessageStore.open(tmp_path / "empty.db")
        try:
            snap = await sweep_store(store, row_cap=1000)
            assert snap.total == 0 and snap.control_ids == frozenset() and snap.error is None
            audit = judge(
                _ledger(accepted=2), snap, moment=MOMENT_POST_MORTEM, sent=2, read_short=2
            )
            assert audit.verdict == VERDICT_PROBE_UNUSABLE
            assert audit.missing_accepted_total == 0
        finally:
            await store.close()

    asyncio.run(go())


# --- the SENDER seam, driven over a real socket ---------------------------------------------------


def test_sender_ledger_records_both_exits_over_a_real_socket() -> None:
    """RUN THE THING at the other end: a real :class:`PersistentConnection` against a real MLLP
    listener that ACKs two frames, NAKs one, and then closes on a fourth without answering.

    All three ledger states have to be reachable from the actual sender, not just constructible: the
    audit's arithmetic assumes CONFIRMED is exactly ``sent - excused``, and that assumption is only
    worth anything if ``_on_ack`` and ``_fail_inflight`` both feed it.
    """
    from harness.load.corpus import Outgoing
    from harness.load.correlator import Correlator
    from harness.load.metrics import Counters, Histogram, LiveMetrics
    from harness.load.sender import PersistentConnection
    from messagefoundry.transports.mllp import MLLPDecoder, frame

    ledger = IntakeLedger()
    metrics = LiveMetrics(Counters(), Histogram(), Histogram())

    async def go() -> None:
        answered = 0

        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            nonlocal answered
            decoder = MLLPDecoder()
            while True:
                chunk = await reader.read(65536)
                if not chunk:
                    break
                for _msg in decoder.feed(chunk):
                    answered += 1
                    if answered > 3:
                        # The fourth frame is swallowed and the socket dropped: the send is left in
                        # `_inflight` and must land in the ledger as UNCONFIRMED.
                        writer.close()
                        return
                    code = "AA" if answered <= 2 else "AE"
                    writer.write(
                        frame(f"MSH|^~\\&|E|E|H|H|20260101||ACK|A{answered}|P|2.5\rMSA|{code}|X\r")
                    )
                    await writer.drain()

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        correlator = Correlator(1000, metrics)
        conn = PersistentConnection(
            "127.0.0.1", port, correlator, metrics, expect_ack=True, ledger=ledger
        )
        conn.start()
        for i in range(4):
            await conn.submit(
                Outgoing(
                    seq=i,
                    code="ADT",
                    control_id=f"LG{i:04d}",
                    payload=f"MSH|^~\\&|A|B|C|D|20260101||ADT^A01|LG{i:04d}|P|2.5\r",
                )
            )
        # Give the exchange time to complete, then stop (which sweeps whatever is still in flight).
        for _ in range(200):
            if ledger.total >= 4:
                break
            await asyncio.sleep(0.01)
        await conn.stop(0.2)
        server.close()
        await server.wait_closed()

    asyncio.run(go())

    accepted = {cid for cid, rec in ledger.confirmed.items() if rec.accepted}
    rejected = {cid for cid, rec in ledger.confirmed.items() if not rec.accepted}
    assert accepted == {"LG0000", "LG0001"}, ledger.confirmed
    assert rejected == {"LG0002"}, ledger.confirmed
    assert set(ledger.unconfirmed) == {"LG0003"}, dict(ledger.unconfirmed)
    # The accounting identity the audit's arithmetic rests on, measured rather than assumed.
    c = metrics.counters
    assert c.sent == c.acked + c.nak + c.timeouts == ledger.total == 4
    assert not ledger.overflow and not ledger.duplicates


def test_ledger_requires_expect_ack() -> None:
    """A ledger with no response frames to record can only ever be empty, and an empty ledger scores
    vacuously clean. Refused loudly at construction instead."""
    from harness.load.correlator import Correlator
    from harness.load.metrics import Counters, Histogram, LiveMetrics
    from harness.load.sender import PersistentConnection

    metrics = LiveMetrics(Counters(), Histogram(), Histogram())
    with pytest.raises(ValueError, match="expect_ack"):
        PersistentConnection(
            "127.0.0.1",
            1,
            Correlator(10, metrics),
            metrics,
            expect_ack=False,
            ledger=IntakeLedger(),
        )


# --- the runner wiring: one definition of the shortfall, and it reaches the artifact --------------


def _sample(read: int) -> EngineSample:
    return EngineSample(
        elapsed_s=0.0,
        pending=0,
        inflight=0,
        done=0,
        dead=0,
        read=read,
        written=0,
        out_dead=0,
        queue_depth=0,
        in_pipeline=0,
        db_size_bytes=0,
        journal_mode="wal",
        synchronous="normal",
        uptime_s=0.0,
    )


def test_read_shortfall_is_the_same_number_the_reconcile_prints() -> None:
    """ONE DEFINITION, asserted rather than assumed.

    The audit exists to explain ``engine_read N < confirmed sent M (lost K on intake)``, so it has to
    fire on exactly that ``K``. A second copy of the unconfirmed-send excusal beside it would let the
    audit trigger on a shortfall the step does not report, or stay silent on one it does -- and either
    way it would be attributing the wrong failure. The excusal is deliberately non-trivial here
    (``timeouts`` inside the budget, so some sends ARE excused), so a version that ignored it would
    not agree by accident.
    """
    c = Counters(sent=40, timeouts=4)
    base, final = _sample(0), _sample(30)

    short = _read_shortfall(c, base, final, unconfirmed_budget=8)
    no_loss = _reconcile(c, base, final, unconfirmed_budget=8)

    assert short == 6  # 40 sent - 4 excused - 30 read
    assert not no_loss.ok
    # The number the failing message actually carries, read back out of the message itself.
    assert f"(lost {short} on intake)" in no_loss.detail
    assert "confirmed sent 36" in no_loss.detail


def test_read_shortfall_is_zero_without_engine_gauges() -> None:
    """No samples means no shortfall to ATTRIBUTE. ``_reconcile`` fails the step on its own for that,
    and the audit must not invent a finding out of a missing measurement."""
    assert _read_shortfall(Counters(sent=10), None, _sample(0), unconfirmed_budget=1) == 0
    assert _read_shortfall(Counters(sent=10), _sample(0), None, unconfirmed_budget=1) == 0


def _record_with(audit: IntakeAudit, *, read: int, sent: int) -> ConnScaleRecord:
    poller = EnginePoller("http://127.0.0.1:1", token=None, origin=0.0)
    poller._samples = [_sample(0), _sample(read)]
    return _build_record(
        claim_mode="per_lane",
        fuse_mode=False,
        batch_mode=False,
        mode="fixed_aggregate",
        count=4,
        aggregate_rate=10.0,
        metrics_counters=Counters(sent=sent),
        ack_hist=Histogram(),
        poller=poller,
        samples=[],
        drain_seconds=1.0,
        reload_seconds=None,
        audit_live=not_run("not triggered", moment=MOMENT_LIVE),
        audit_final=audit,
    )


def test_a_failing_reconcile_carries_the_audit_verdict_into_its_own_message() -> None:
    """The deliverable: a CI reader gets the attribution WITHOUT re-running anything.

    ``no_loss.ok`` is untouched -- the count check still fails the step exactly as before -- but its
    detail, which is what the smoke's assertion message prints, now says WHICH branch it was.
    """
    led = _ledger(accepted=4)
    audit = judge(
        led,
        StoreSnapshot(frozenset(list(led.confirmed)[1:]), 3),
        moment=MOMENT_POST_MORTEM,
        sent=4,
        read_short=1,
    )
    rec = _record_with(audit, read=3, sent=4)

    assert rec.no_loss.ok is False  # unchanged: the count check still fails
    assert "lost 1 on intake" in rec.no_loss.detail  # the original message survives verbatim
    assert "INVARIANT_SUSPECT" in rec.no_loss.detail  # and now says which branch
    assert "seqs=[0]" in rec.no_loss.detail
    assert rec.intake_audit is audit and rec.intake_audit.engine_suspect
    assert "intake_audit" in rec.to_json_dict()


def test_a_passing_reconcile_is_left_byte_identical() -> None:
    """No verdict is appended to a detail that reports no problem: the audit rides in its own field
    and on the console, and a clean step's ``no_loss`` string is unchanged from pre-#1292."""
    led = _ledger(accepted=4)
    audit = judge(
        led, StoreSnapshot(_all_ids(led), 4), moment=MOMENT_POST_MORTEM, sent=4, read_short=0
    )
    rec = _record_with(audit, read=4, sent=4)
    assert rec.no_loss.ok
    assert rec.no_loss.detail == "read>=sent, sink_received>=written, backlog drained"


# --- the SLO: a green must not be earned by an audit that never ran ------------------------------


def _profile(intake_audit: bool = True) -> object:
    flag = "true" if intake_audit else "false"
    return load_connscale_profile_text(
        "[connscale]\n"
        'name = "slo-it"\n'
        "counts = [4]\n"
        "base_port = 41000\n"
        "aggregate_rate = 10.0\n"
        f"intake_audit = {flag}\n"
        "\n"
        "[connscale.slo]\n"
        "zero_loss = false\n"
    )


def _slo(record: ConnScaleRecord, *, enabled: bool = True) -> SloCheck | None:
    checks = _evaluate_slos(_profile(enabled), [record])  # type: ignore[arg-type]
    return next((c for c in checks if c.name == "intake_audit"), None)


def test_slo_fails_on_a_suspect_record_and_names_the_sequence_numbers() -> None:
    led = _ledger(accepted=4)
    audit = judge(
        led,
        StoreSnapshot(frozenset(list(led.confirmed)[1:]), 3),
        moment=MOMENT_POST_MORTEM,
        sent=4,
        read_short=1,
    )
    check = _slo(_record_with(audit, read=3, sent=4))
    assert check is not None and not check.ok
    assert "INVARIANT_SUSPECT" in str(check.observed) and "seqs=[0]" in str(check.observed)


def test_slo_states_its_scope_rather_than_claiming_a_bare_clean() -> None:
    """A GREEN THAT MEANS LESS, headed off. ``_evaluate_slos`` is shared with the batch-box aggregate,
    whose records carry a NOT_RUN audit by construction (its driver processes poll a REMOTE engine and
    have no store to read). A bare "clean" there would be a pass earned by nothing, so the observation
    always names how many steps were actually audited -- and zero-audited says so in those words."""
    led = _ledger(accepted=4)
    clean = judge(
        led, StoreSnapshot(_all_ids(led), 4), moment=MOMENT_POST_MORTEM, sent=4, read_short=0
    )
    audited = _slo(_record_with(clean, read=4, sent=4))
    assert audited is not None and audited.ok
    assert str(audited.observed) == "clean (1 of 1 step(s) audited)"

    never = _slo(_record_with(not_run("audit not wired"), read=4, sent=4))
    assert never is not None and never.ok  # not a FAILURE -- but it must not read as a finding
    assert "NOT AUDITED" in str(never.observed) and "0 of 1" in str(never.observed)


def test_slo_is_absent_when_the_profile_turns_the_audit_off() -> None:
    led = _ledger(accepted=4)
    clean = judge(
        led, StoreSnapshot(_all_ids(led), 4), moment=MOMENT_POST_MORTEM, sent=4, read_short=0
    )
    assert _slo(_record_with(clean, read=4, sent=4), enabled=False) is None


# --- the sweep's short-page limb -----------------------------------------------------------------


def test_sweep_reports_truncated_when_a_page_returns_fewer_rows_than_counted() -> None:
    """``COUNT(*)`` promised more rows than the pages delivered. Returning the short set would read as
    absence for every row the sweep never reached -- the same catastrophic false positive the
    empty-read guard exists for, one page further in."""

    class _ShortStore:
        async def count_messages(self) -> int:
            return 5

        async def list_messages(self, *, limit: int, offset: int) -> list[dict[str, object]]:
            return [{"control_id": "A"}] if offset == 0 else []

    snap = asyncio.run(sweep_store(_ShortStore(), row_cap=100))
    assert snap.truncated and snap.total == 5 and snap.control_ids == frozenset({"A"})
    verdict = judge(
        _ledger(accepted=5), snap, moment=MOMENT_POST_MORTEM, sent=5, read_short=4
    ).verdict
    assert verdict == VERDICT_PROBE_UNUSABLE
