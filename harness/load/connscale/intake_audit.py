# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The intake audit (BACKLOG #1292) -- a PER-MESSAGE discriminator for an ``engine_read`` shortfall.

WHAT IT IS FOR. ``harness.load.connscale.runner._reconcile`` fails a step with
``engine_read {read} < confirmed sent {sent - excused} (lost N on intake)``. That message is a
COUNT-vs-COUNT comparison and it cannot be attributed after the fact: the shortfall reads identically
whether the engine lost an acknowledged message (the count-and-log invariant, a real defect) or the
harness's own ``engine_read`` gauge was sampled early / summed short (an instrument defect). This
module asks a DIFFERENT question -- *is THIS message's row there* -- so that the two separate.

WHY NOT ANOTHER COUNT. ``engine_read`` is ALREADY ``COUNT(*) FROM messages`` for the run's channels,
sampled through two HTTP layers: the store's ``_collect_connection_metrics`` -> the engine's
``connection_metrics_view`` -> ``GET /connections``'s ``read`` field -> ``enginepoll``'s re-sum of the
per-inbound rows. A probe that counted rows would re-derive the number already under dispute. This
one compares SETS of control ids.

WHAT THE SENDER CONTRIBUTES. :class:`IntakeLedger` is filled by
:class:`~harness.load.sender.PersistentConnection` at the two points where a send LEAVES ``_inflight``:

* CONFIRMED -- a response frame was read back for it (``_on_ack``), carrying its MSA-1 code and
  whether that code was an accept. Measured on this rig the accounting identity
  ``sent == acked + nak + timeouts`` holds exactly, so the confirmed set is precisely
  ``sent - excused`` -- the same quantity ``_reconcile`` bounds. Matching the reconcile's own
  arithmetic is the point; keying on ``acked`` alone would answer a neighbouring question.
* UNCONFIRMED -- still outstanding when the connection closed (``_fail_inflight``), which the
  reconcile EXCUSES. Reported separately, and the subset that turns out to be in the store
  (``late_unconfirmed_total``) is the honest measure of how loose that excusal is.

WHAT IT DOES NOT ASSERT. A confirmed send whose MSA-1 was a REJECT and whose row is absent is NOT an
engine finding, and is reported as :data:`VERDICT_CORRELATION_SUSPECT` rather than as loss. Several of
the NAK limbs in ``pipeline/wiring_runner.py`` write their ``messages`` row with ``control_id=None``
(the decode-error, NUL, parse-failure and oversize paths record the row BEFORE anything parsed an
MSH-10), so such a row EXISTS but is unfindable by control id. A rejected message is therefore
expected to be unmatchable here, and only the ACCEPTED-and-absent set carries the count-and-log
invariant.

PHI. ``report.py`` states the rule for this artifact family: metrics and metadata only, never message
bodies and never control-id lists. So the audit reports SEQUENCE NUMBERS (dense integers minted by
the harness's own counter, meaningless outside the run) and the DISTINCT MSA-1 codes involved -- both
sufficient to act on, neither a control-id list. **Control ids are not emitted ANYWHERE -- not to the
artifact, not to the log.** Said explicitly because the earlier wording here promised they "stay in
the harness log line", which was false in both directions: a reader who went looking for them found
none, and a maintainer reconciling the prose against the code would have made it true by logging
them, which is precisely what the rule above forbids. A run is reproduced from the seqs and the
profile, never from an identifier list.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any, Final

log = logging.getLogger(__name__)

#: When the audit was taken. Running BOTH is what removes the ambiguity: ``live`` still has the engine
#: up (so "we sampled too early" is available as an explanation), ``post_mortem`` runs against the
#: stopped, committed store (so it is not).
MOMENT_LIVE: Final = "live"
MOMENT_POST_MORTEM: Final = "post_mortem"

#: The audit did not run (disabled by profile, or the live moment was not triggered).
VERDICT_NOT_RUN: Final = "NOT_RUN"
#: The probe itself could not answer. NEVER read as loss -- see :func:`judge` for the ordering rule.
VERDICT_PROBE_UNUSABLE: Final = "PROBE_UNUSABLE"
#: Every confirmed send has a row, and the reconcile saw no shortfall either.
VERDICT_INTAKE_COMPLETE: Final = "INTAKE_COMPLETE"
#: A shortfall was reported, yet every confirmed send HAS a row -> the ``engine_read`` gauge, not the
#: engine, is short. A harness/instrument defect (sample attribution or sum coverage).
VERDICT_SAMPLING_LAG: Final = "SAMPLING_LAG"
#: A shortfall was reported and it is wholly accounted for by sends that were NEVER CONFIRMED, so it
#: implicates neither intake nor the gauge. Split out from :data:`VERDICT_SAMPLING_LAG` because the
#: runner's excusal clamps ``excused`` to 0 once the unconfirmed count exceeds its budget, and the
#: shortfall handed here then consists of sends the engine may never have seen. Blaming the gauge for
#: those named an instrument that was exactly right, and CONTRADICTED the reconcile text this verdict
#: is appended to -- which already calls that step a systemic no-ACK fault.
VERDICT_UNCONFIRMED_SHORTFALL: Final = "UNCONFIRMED_SHORTFALL"
#: A send the engine ACCEPT-ACKed has no ``messages`` row -> the count-and-log invariant would be
#: broken. The engine branch, and the only one that justifies the P1.
VERDICT_INVARIANT_SUSPECT: Final = "INVARIANT_SUSPECT"
#: Only REJECT-ACKed sends are unmatched -> the harness's frame-to-message correspondence, or the
#: ``control_id=None`` NAK limbs above. Not an engine finding.
VERDICT_CORRELATION_SUSPECT: Final = "CORRELATION_SUSPECT"

#: How many sends one ledger holds before it stops recording and declares itself overflowed. A ledger
#: that silently stopped recording would render as a clean audit, so overflow is a PROBE_UNUSABLE
#: input, not a shrug.
DEFAULT_LEDGER_CAPACITY: Final = 500_000

#: How many sequence numbers a verdict names. The COUNT is always exact and reported beside the
#: sample, so a truncated list never understates the finding.
SAMPLE_CAP: Final = 32

_PAGE = 1000  # rows per list_messages page during the store sweep


@dataclass(frozen=True)
class ConfirmedSend:
    """One send for which the harness READ A RESPONSE FRAME back, with what that frame said."""

    seq: int
    code: str  # MSA-1 verbatim ("" when the frame carried no parsable MSA-1)
    accepted: bool  # the sender's OWN accept decision, passed in rather than re-derived here


class IntakeLedger:
    """Per-message record of what the sender observed, keyed by control id (MSH-10).

    Written only from the event loop (``PersistentConnection._on_ack`` / ``_fail_inflight``), so no
    locking. Optional on the connection and ``None`` by default -- the same seam ``tracker`` uses --
    so the steady-state write path is unchanged when no audit is wanted.
    """

    __slots__ = ("_capacity", "_confirmed", "_duplicates", "_overflow", "_unconfirmed")

    def __init__(self, *, capacity: int = DEFAULT_LEDGER_CAPACITY) -> None:
        if capacity < 1:
            raise ValueError("ledger capacity must be >= 1")
        self._capacity = capacity
        self._confirmed: dict[str, ConfirmedSend] = {}
        self._unconfirmed: dict[str, int] = {}
        self._overflow = 0
        self._duplicates = 0

    def record_confirmed(self, control_id: str, seq: int, code: str, *, accepted: bool) -> None:
        """A response frame was read for ``control_id``. ``accepted`` is the SENDER's decision."""
        if self._reject(control_id):
            return
        self._confirmed[control_id] = ConfirmedSend(seq, code, accepted)

    def record_unconfirmed(self, control_id: str, seq: int) -> None:
        """``control_id`` was still in flight when its connection closed (the reconcile excuses it)."""
        if self._reject(control_id):
            return
        self._unconfirmed[control_id] = seq

    def _reject(self, control_id: str) -> bool:
        """Refuse a record, counting WHY. Both counters feed PROBE_UNUSABLE rather than being
        absorbed: a ledger that quietly stopped recording, or one whose keys are not unique, produces
        a clean-looking set comparison that means nothing."""
        if len(self._confirmed) + len(self._unconfirmed) >= self._capacity:
            self._overflow += 1
            return True
        if control_id in self._confirmed or control_id in self._unconfirmed:
            self._duplicates += 1
            return True
        return False

    @property
    def confirmed(self) -> Mapping[str, ConfirmedSend]:
        return self._confirmed

    @property
    def unconfirmed(self) -> Mapping[str, int]:
        return self._unconfirmed

    @property
    def total(self) -> int:
        """Sends accounted for. Compared against ``sent`` -- a mismatch means the ledger is partial,
        which invalidates a NULL result (though not a positive one)."""
        return len(self._confirmed) + len(self._unconfirmed)

    @property
    def overflow(self) -> int:
        return self._overflow

    @property
    def duplicates(self) -> int:
        return self._duplicates


@dataclass(frozen=True)
class StoreSnapshot:
    """What one read of the step's own store returned.

    ``error`` and ``truncated`` are carried BESIDE the data, never folded into it: an empty
    ``control_ids`` is produced identically by a working sweep of an empty store and by a broken
    query, and those warrant opposite verdicts.
    """

    control_ids: frozenset[str]
    total: int  # COUNT(*) of the messages table -- the sweep's positive control
    truncated: bool = False
    error: str | None = None


StoreReader = Callable[[], Awaitable[StoreSnapshot]]


@dataclass(frozen=True)
class IntakeAudit:
    """One audit: the verdict, its inputs, and enough detail to act on without re-running."""

    moment: str
    verdict: str
    read_short: int  # the reconcile shortfall this audit was taken against
    sent: int
    confirmed_total: int
    unconfirmed_total: int
    store_total: int
    missing_accepted_total: int
    missing_rejected_total: int
    late_unconfirmed_total: int
    missing_accepted_seqs: tuple[int, ...] = ()  # bounded sample; the totals above are exact
    missing_rejected_seqs: tuple[int, ...] = ()
    missing_codes: tuple[str, ...] = ()  # DISTINCT MSA-1 codes across the missing set, sorted
    detail: str = ""

    @property
    def conclusive(self) -> bool:
        """Did this audit actually answer the question? PROBE_UNUSABLE and NOT_RUN did not, and must
        never be read as a pass."""
        return self.verdict in (
            VERDICT_INTAKE_COMPLETE,
            VERDICT_SAMPLING_LAG,
            VERDICT_UNCONFIRMED_SHORTFALL,
            VERDICT_INVARIANT_SUSPECT,
            VERDICT_CORRELATION_SUSPECT,
        )

    @property
    def engine_suspect(self) -> bool:
        """Is this the branch that implicates the ENGINE (vs the harness or the probe)?

        THE MOMENT IS PART OF THE CLAIM, not a caveat on it. A LIVE sweep pages over a store still
        being written and can miss a row that is present, so a live INVARIANT_SUSPECT is not by
        itself an engine finding -- ``_conclusion`` already says so in the prose. Requiring the
        post-mortem here makes the machine surface agree with that text BY CONSTRUCTION rather than
        by the SLO gate happening to read the post-mortem field, which is an invariant maintained by
        a distant call site and would break silently if another reader picked the live one.
        """
        return self.verdict == VERDICT_INVARIANT_SUSPECT and self.moment == MOMENT_POST_MORTEM

    def summary(self) -> str:
        """One line a CI reader can act on without re-running anything."""
        return (
            f"intake audit [{self.moment}] {self.verdict}: {self.detail} "
            f"(sent={self.sent} confirmed={self.confirmed_total} "
            f"unconfirmed={self.unconfirmed_total} store_rows={self.store_total} "
            f"missing_accepted={self.missing_accepted_total} "
            f"missing_rejected={self.missing_rejected_total} "
            f"late_unconfirmed={self.late_unconfirmed_total} "
            f"seqs={list(self.missing_accepted_seqs)} codes={list(self.missing_codes)})"
        )

    def to_json_dict(self) -> dict[str, object]:
        return {
            "moment": self.moment,
            "verdict": self.verdict,
            "read_short": self.read_short,
            "sent": self.sent,
            "confirmed": self.confirmed_total,
            "unconfirmed": self.unconfirmed_total,
            "store_total": self.store_total,
            "missing_accepted": self.missing_accepted_total,
            "missing_rejected": self.missing_rejected_total,
            "late_unconfirmed": self.late_unconfirmed_total,
            # Sequence numbers, not control ids (PHI rule, see the module docstring). Bounded sample.
            "missing_accepted_seqs": list(self.missing_accepted_seqs),
            "missing_rejected_seqs": list(self.missing_rejected_seqs),
            "missing_codes": list(self.missing_codes),
            "detail": self.detail,
        }


def not_run(reason: str, *, moment: str = MOMENT_POST_MORTEM) -> IntakeAudit:
    """The audit was not taken. Distinct from a clean audit AND from an unusable one."""
    return IntakeAudit(
        moment=moment,
        verdict=VERDICT_NOT_RUN,
        read_short=0,
        sent=0,
        confirmed_total=0,
        unconfirmed_total=0,
        store_total=0,
        missing_accepted_total=0,
        missing_rejected_total=0,
        late_unconfirmed_total=0,
        detail=reason,
    )


def _conclusion(moment: str) -> str:
    """What an accept-ACKed-but-absent row is ALLOWED to conclude, which depends on the moment.

    Only the post-mortem may state the engine finding. ``sweep_store`` pages with ``ORDER BY
    received_at DESC`` + OFFSET, so a row committed while a LIVE sweep is walking shifts the window
    and a genuinely present row can go unread -- the module docstring records this as known and
    deliberate, and it manufactures exactly this verdict. The live text therefore reports the same
    observation without the conclusion, so a console line or a JSON artifact cannot be quoted as an
    invariant violation the post-mortem beside it does not support.
    """
    if moment == MOMENT_POST_MORTEM:
        return (
            "the engine was STOPPED and its store committed when this was read, so on a deployment "
            "the count-and-log invariant would not hold for those messages"
        )
    return (
        "NOT an engine finding on its own: this LIVE read pages over a store still being written "
        "and can miss a row that is present, so it stands only if the post-mortem reproduces it"
    )


def judge(
    ledger: IntakeLedger,
    snapshot: StoreSnapshot,
    *,
    moment: str,
    sent: int,
    read_short: int,
    unexplained_short: int | None = None,
) -> IntakeAudit:
    """Turn a ledger + one store read into a verdict. Pure -- the whole decision table, unit-testable.

    THE ORDERING IS THE DESIGN, not an accident of writing. A POSITIVE finding is self-evidencing; a
    NULL is printed identically by every silent instrument failure, so each way the probe can be
    blind is ruled out BEFORE a null is allowed to mean anything:

    1. the sender-side ledger is overflowed / non-unique / empty -> PROBE_UNUSABLE.
    2. NOTHING was ever confirmed -> PROBE_UNUSABLE. The ledger-side positive control, and separate
       from step 1 on purpose: the compared set is ``confirmed``, so a ledger holding only
       unconfirmed sends is non-empty by ``total`` and still compares NOTHING.
    3. the store sweep failed or was truncated -> PROBE_UNUSABLE.
    4. the store sweep read ZERO rows against a non-empty ledger -> PROBE_UNUSABLE. The store-side
       positive control, checked HERE so a broken query renders as "unusable" and never as "every
       message is missing" -- the worst possible false positive to hang a P1 on.
    5. an ACCEPT-ACKed send with no row -> INVARIANT_SUSPECT. Checked BEFORE the partial-ledger guard
       below: a short ledger under-reports, so a finding inside it is still a real finding.
    6. only REJECT-ACKed sends unmatched -> CORRELATION_SUSPECT (see the module docstring).
    7. the ledger did not account for every send -> PROBE_UNUSABLE, because a null over a partial
       ledger proves nothing. This is step 5's mirror image, and why the two are split rather than
       both being checked up front.
    8. a shortfall with NOTHING left unexplained once the never-confirmed sends are set aside ->
       UNCONFIRMED_SHORTFALL. ``unexplained_short`` is supplied by the PRODUCER, which alone knows
       whether its excusal was clamped; this step must not infer it from the unconfirmed count,
       because in-budget those sends are already subtracted out of ``read_short`` and the guess
       silences a real gauge finding on the common path.
    9. a shortfall with an unexplained remainder, every confirmed send present -> SAMPLING_LAG: that
       remainder is in the gauge, not intake.
    10. otherwise INTAKE_COMPLETE.
    """
    confirmed = ledger.confirmed
    unconfirmed_count = len(ledger.unconfirmed)
    ledger_total = ledger.total
    store_ids = snapshot.control_ids
    unexplained = read_short if unexplained_short is None else unexplained_short

    def _unusable(detail: str) -> IntakeAudit:
        return _build(
            moment=moment,
            verdict=VERDICT_PROBE_UNUSABLE,
            read_short=read_short,
            sent=sent,
            ledger=ledger,
            snapshot=snapshot,
            missing_accepted=(),
            missing_rejected=(),
            late_unconfirmed=0,
            detail=detail,
        )

    if ledger.overflow:
        return _unusable(
            f"the send ledger overflowed after {ledger_total} entries ({ledger.overflow} send(s) "
            f"unrecorded), so an absent control id cannot be told from an unrecorded one"
        )
    if ledger.duplicates:
        return _unusable(
            f"{ledger.duplicates} duplicate control id(s) reached the ledger -- the ids are not "
            f"unique this run, so set membership does not identify a message"
        )
    if ledger_total == 0 and sent > 0:
        return _unusable(
            f"the send ledger recorded NOTHING against {sent} counted send(s) -- the sender-side "
            f"instrument did not run, so a clean set comparison here would be vacuous"
        )
    if not confirmed and sent > 0:
        # THE POSITIVE CONTROL FOR THE LEDGER SIDE, and it must test `confirmed` rather than
        # `ledger_total`: every finding branch below iterates `confirmed` and NOTHING reads
        # `unconfirmed` except as a count, so a ledger holding only unconfirmed sends compares an
        # EMPTY set and every verdict it could reach would be true of nothing. The guard above does
        # not cover this -- it fires only when the ledger is empty outright. Reachable on the
        # harness's own headline fault: when the runner's excusal goes over budget it clamps
        # `excused` to 0, so a step where no send was ever ACKed arrives here with a large
        # `read_short`, and without this it returned a CONCLUSIVE "not in intake" over zero
        # elements -- clearing intake on exactly the step the reconcile calls a possible
        # accepted-and-dropped.
        return _unusable(
            f"NO send was ever confirmed against {sent} counted send(s) ({len(ledger.unconfirmed)} "
            f"unconfirmed) -- the compared set is empty, so no verdict here could distinguish a "
            f"clean intake from a lost one"
        )
    if snapshot.error is not None:
        return _unusable(f"the store sweep failed: {snapshot.error}")
    if snapshot.truncated:
        return _unusable(
            f"the store sweep was truncated at {len(store_ids)} of {snapshot.total} row(s) -- the "
            f"unread remainder is indistinguishable from absence"
        )
    if snapshot.total == 0 and ledger_total > 0:
        return _unusable(
            f"the store sweep read 0 row(s) against {ledger_total} accounted send(s) -- the query "
            f"answered nothing rather than the store being empty; reported as unusable, NOT as "
            f"{ledger_total} lost messages"
        )

    missing_accepted = tuple(
        sorted(
            (rec.seq, rec.code)
            for cid, rec in confirmed.items()
            if rec.accepted and cid not in store_ids
        )
    )
    missing_rejected = tuple(
        sorted(
            (rec.seq, rec.code)
            for cid, rec in confirmed.items()
            if not rec.accepted and cid not in store_ids
        )
    )
    late_unconfirmed = sum(1 for cid in ledger.unconfirmed if cid in store_ids)

    def _matched(verdict: str, detail: str) -> IntakeAudit:
        """The three MATCHED outcomes -- every confirmed send accounted for -- differ only in verdict
        and prose. Collapsed for the same reason ``_unusable`` above is: three adjacent hand-rolled
        blocks differing in one constant make a divergence in a copied argument read as normal, and
        that divergence is not hypothetical here (``_unusable`` deliberately passes
        ``late_unconfirmed=0`` while these pass the computed value)."""
        return _build(
            moment=moment,
            verdict=verdict,
            read_short=read_short,
            sent=sent,
            ledger=ledger,
            snapshot=snapshot,
            missing_accepted=(),
            missing_rejected=(),
            late_unconfirmed=late_unconfirmed,
            detail=detail,
        )

    if missing_accepted:
        partial = (
            ""
            if ledger_total == sent
            else f" (the ledger accounted {ledger_total} of {sent} send(s), so this is a LOWER BOUND)"
        )
        return _build(
            moment=moment,
            verdict=VERDICT_INVARIANT_SUSPECT,
            read_short=read_short,
            sent=sent,
            ledger=ledger,
            snapshot=snapshot,
            missing_accepted=missing_accepted,
            missing_rejected=missing_rejected,
            late_unconfirmed=late_unconfirmed,
            detail=(
                f"{len(missing_accepted)} send(s) the engine ACCEPT-ACKed have no messages row in "
                f"its own store ({snapshot.total} row(s) present){partial} -- {_conclusion(moment)}"
            ),
        )
    if missing_rejected:
        return _build(
            moment=moment,
            verdict=VERDICT_CORRELATION_SUSPECT,
            read_short=read_short,
            sent=sent,
            ledger=ledger,
            snapshot=snapshot,
            missing_accepted=(),
            missing_rejected=missing_rejected,
            late_unconfirmed=late_unconfirmed,
            detail=(
                f"{len(missing_rejected)} REJECT-ACKed send(s) are unmatched and no accepted send "
                f"is -- not an engine finding: a rejected message may be recorded with a NULL "
                f"control id, and the harness pops response frames strictly FIFO"
            ),
        )
    if ledger_total != sent:
        return _unusable(
            f"the send ledger accounted {ledger_total} of {sent} counted send(s) -- a clean set "
            f"comparison over a partial ledger cannot exclude a loss among the "
            f"{sent - ledger_total} it never saw"
        )
    # NAMING THE GAUGE IS A POSITIVE CLAIM, so it is made only for the part of the shortfall no
    # excusal can forgive -- and that part is COMPUTED BY THE PRODUCER, never inferred here. The
    # runner's excusal clamps `excused` to 0 over budget and then hands on a bare int, so
    # `read_short` alone cannot say which world it describes: in-budget the unconfirmed sends are
    # already subtracted out of it, over-budget they are still inside it. Guessing from the
    # unconfirmed COUNT gets the common in-budget case backwards and silences a real gauge finding.
    # `None` means the producer did not say; then every missing message is the gauge's to answer
    # for, which is the pre-existing behaviour and errs toward a HARNESS finding rather than
    # toward silence.
    if read_short > 0 and unexplained <= 0:
        return _matched(
            VERDICT_UNCONFIRMED_SHORTFALL,
            f"engine_read is short by {read_short}, and once the {unconfirmed_count} never-"
            f"confirmed send(s) are set aside NOTHING is left unaccounted for -- so the shortfall "
            f"implicates NEITHER intake NOR the engine_read gauge. All {len(confirmed)} confirmed "
            f"send(s) have a messages row ({snapshot.total} row(s) present, {late_unconfirmed} "
            f"unconfirmed send(s) arrived anyway)",
        )
    if read_short > 0:
        return _matched(
            VERDICT_SAMPLING_LAG,
            f"engine_read is short by {read_short}, of which {unexplained} remain(s) unaccounted "
            f"for after the {unconfirmed_count} never-confirmed send(s) are set aside, yet all "
            f"{len(confirmed)} confirmed send(s) HAVE a messages row ({snapshot.total} row(s) "
            f"present) -- that remainder is in the engine_read gauge (sample attribution or "
            f"per-inbound sum coverage), not in intake",
        )
    return _matched(
        VERDICT_INTAKE_COMPLETE,
        f"all {len(confirmed)} confirmed send(s) have a messages row; {snapshot.total} row(s) "
        f"present, {late_unconfirmed} excused send(s) arrived anyway",
    )


def _build(
    *,
    moment: str,
    verdict: str,
    read_short: int,
    sent: int,
    ledger: IntakeLedger,
    snapshot: StoreSnapshot,
    missing_accepted: tuple[tuple[int, str], ...],
    missing_rejected: tuple[tuple[int, str], ...],
    late_unconfirmed: int,
    detail: str,
) -> IntakeAudit:
    # "(none)" rather than "" so an unparsable MSA-1 is a NAMED cause in the artifact instead of an
    # empty string a reader would take for a serialization gap.
    codes = sorted({code or "(none)" for _seq, code in (*missing_accepted, *missing_rejected)})
    return IntakeAudit(
        moment=moment,
        verdict=verdict,
        read_short=read_short,
        sent=sent,
        confirmed_total=len(ledger.confirmed),
        unconfirmed_total=len(ledger.unconfirmed),
        store_total=snapshot.total,
        missing_accepted_total=len(missing_accepted),
        missing_rejected_total=len(missing_rejected),
        late_unconfirmed_total=late_unconfirmed,
        missing_accepted_seqs=tuple(seq for seq, _code in missing_accepted[:SAMPLE_CAP]),
        missing_rejected_seqs=tuple(seq for seq, _code in missing_rejected[:SAMPLE_CAP]),
        missing_codes=tuple(codes),
        detail=detail,
    )


async def run_intake_audit(
    ledger: IntakeLedger,
    reader: StoreReader,
    *,
    moment: str,
    sent: int,
    read_short: int,
    unexplained_short: int | None = None,
) -> IntakeAudit:
    """Read the store once through ``reader`` and judge.

    A reader failure becomes a PROBE_UNUSABLE snapshot rather than an exception: the audit is an
    instrument, and an instrument must never fail the run it was added to diagnose.
    """
    try:
        snapshot = await reader()
    except Exception as exc:  # noqa: BLE001 - any reader failure is a probe outcome, not a run failure
        snapshot = StoreSnapshot(frozenset(), 0, error=f"{type(exc).__name__}: {exc}")
    audit = judge(
        ledger,
        snapshot,
        moment=moment,
        sent=sent,
        read_short=read_short,
        unexplained_short=unexplained_short,
    )
    if audit.verdict != VERDICT_INTAKE_COMPLETE:
        log.warning("%s", audit.summary())
    return audit


async def sweep_store(store: Any, *, row_cap: int) -> StoreSnapshot:
    """Collect every ``control_id`` in ``store``'s ``messages`` table, unfiltered and paged.

    UNFILTERED BY CHANNEL, DELIBERATELY. The connscale runner gives each SQLite step its own DB file
    and empties the shared server store before each step, so this store holds exactly this step's
    rows. Filtering by the LIVE inbound registry -- the natural-looking choice -- would reproduce the
    exact blind spot the audit exists to detect: the API emits a ``read`` figure only for a channel
    still present in ``rr.registry.inbound``, so a row whose channel left the registry (the mid-hold
    reload probe) is committed but uncounted. An unfiltered sweep SEES that row.

    ``row_cap`` bounds the work: a table larger than the cap is reported TRUNCATED rather than
    partially swept, because an unread remainder is indistinguishable from absence.

    ``control_id`` is stored in CLEARTEXT (``_insert_message`` ciphers only raw/error/summary/
    metadata), so this reads an encrypted store unchanged. Typed against the ``Store`` PROTOCOL
    surface (``count_messages``/``list_messages``) rather than a backend, so SQLite and the two
    server backends go down one path.

    KNOWN AND DELIBERATE: the paging is ``ORDER BY received_at DESC`` + OFFSET, so a row committed
    WHILE the sweep is walking lands at offset 0 and shifts the window, which can drop the last page's
    final row. That is why :data:`MOMENT_POST_MORTEM` -- taken after the engine process has exited, so
    no insert is possible -- is the authoritative moment and the one the CI assertion reads. A LIVE
    sweep can therefore report a message it did not actually miss; the live/post-mortem DELTA is
    diagnostic rather than a defect, and a live finding that the post-mortem does not reproduce is
    itself evidence about timing.
    """
    total = int(await store.count_messages())
    if total > row_cap:
        return StoreSnapshot(frozenset(), total, truncated=True)
    ids: set[str] = set()
    offset = 0
    while offset < total:
        rows = await store.list_messages(limit=_PAGE, offset=offset)
        if not rows:
            # Fewer rows than COUNT(*) promised. Report TRUNCATED rather than returning a short set
            # that would read as absence for every row the sweep never reached.
            return StoreSnapshot(frozenset(ids), total, truncated=True)
        for row in rows:
            # Unguarded on purpose: all three backends project `control_id` in `list_messages`. If
            # one ever stopped, the KeyError becomes a PROBE_UNUSABLE snapshot in `run_intake_audit`
            # -- which is the right verdict for a probe that cannot read its own key, and far better
            # than a `.get()` default that would render every row as an absent control id.
            cid = row["control_id"]
            if cid:
                ids.add(str(cid))
        offset += len(rows)
    return StoreSnapshot(frozenset(ids), total)
