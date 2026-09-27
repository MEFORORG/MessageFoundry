# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Directory session reconciliation — the pure decision layer (ADR 0079 mechanism 2).

Disabling an account in Active Directory does **not** terminate its live engine session: once an
opaque token is minted the directory is never re-consulted, so the session keeps working — and keeps
refreshing — up to the flat ``[auth].session_absolute_hours`` cap. This module holds the arithmetic
that decides what a reconciliation pass would do; the I/O (LDAP probes, store writes, audit) lives in
:meth:`~messagefoundry.auth.service.AuthService.reconcile_directory_sessions`, and the timer lives in
the API lifespan. Splitting it this way keeps the two properties that matter — **fail-open** and the
**mass-revoke circuit breaker** — directly testable without a directory or a store.

Four safety properties are built in, in order of importance:

1. **Fail-OPEN on directory unavailability.** An unreachable DC yields
   :attr:`ProbeOutcome.UNAVAILABLE`, which never contributes a strike and never revokes. A
   fail-closed re-check would turn a directory blip into a total console outage during exactly the
   incident when operators need the console.
2. **Two-strike before revoking.** A search that matched nothing cannot tell *deleted* from *moved
   out of the search base* or *a search base that was never right*, so one such result must not
   revoke. A set disabled bit and an unreadable ``userAccountControl`` strike the same way.
3. **A hold on an undetermined wave (ADR 0195).** A bind account that loses read on
   ``userAccountControl`` makes every entry it can no longer read :attr:`ProbeOutcome.UNDETERMINED`
   at once. :func:`hold_engaged` holds those accounts, and only those: none of them is revoked, and
   the rest of the estate is reconciled as usual. The mass-revoke breaker below cannot do this on a
   small estate, because its absolute floor lets five or fewer revocations through.
4. **A mass-revoke circuit breaker.** A misconfigured search base or a moved OU returns "not found"
   for **every** user, which looks the same as "everyone was deleted". :func:`breaker_tripped`
   aborts such a pass wholesale rather than signing out the estate. This is why the pass is
   planned in full before anything is written: an abort must leave the store byte-identical,
   including the role re-diff.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace
from enum import Enum

#: Cap on the strike/last-probed bookkeeping so a long-lived process with heavy user churn cannot
#: grow it without bound (the ``_action_step_up_grants`` / ``_new_ip_seen`` precedent). Entries are
#: pruned to the current candidate set every pass, so this only bites on a pathological estate.
LEDGER_MAX = 10_000


class ProbeOutcome(Enum):
    """What one directory probe of one principal established."""

    #: The principal resolved — the account exists and ``auth.ldap._account_enabled`` passes it.
    #: Carries the current group set, so the role re-diff is free.
    PRESENT = "present"
    #: The entry was found and its ``userAccountControl`` read, with the disabled bit set. Plans
    #: exactly as :attr:`ABSENT` does: it strikes, and revokes at the threshold.
    DISABLED = "disabled"
    #: The entry was found and its ``userAccountControl`` was absent, empty or not an integer
    #: (BACKLOG #1639). A single one beside readable answers strikes and revokes like :attr:`ABSENT`;
    #: a wave of them is held (ADR 0195, :func:`hold_engaged`).
    UNDETERMINED = "undetermined"
    #: The lookup matched nothing, or an id-keyed probe held a stored ``objectGUID`` that could not
    #: be parsed, so no search ran. **Ambiguous**: deleted, moved out of the search base, or a search
    #: base that was never right. Strikes, never revokes on its own. Since ADR 0195 a disabled or an
    #: unreadable entry is NOT this outcome.
    ABSENT = "absent"
    #: The directory could not be consulted (``LdapError`` — connectivity/bind/config). Contributes
    #: nothing: no strike, no revocation, no strike reset.
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class Probe:
    """One principal's probe result. ``groups`` is populated only for :attr:`ProbeOutcome.PRESENT`.

    ``username`` is the name **stored on the row**, which since BACKLOG #1471 is a cached label rather
    than the key the probe was issued on. ``directory_username`` is the name the **directory** reported
    for the same account, populated only for :attr:`ProbeOutcome.PRESENT` -- the two differ exactly
    when the directory renamed the account since the row was last refreshed (BACKLOG #1532).
    """

    user_id: str
    username: str
    outcome: ProbeOutcome
    groups: frozenset[str] = frozenset()
    directory_username: str | None = None


@dataclass(frozen=True)
class UsernameRefresh:
    """One planned refresh of a row's cached ``username`` after a directory-side rename (#1532).

    **Not a revocation, and it must never be counted as one.** It leaves the account, its sessions and
    its roles alone; it copies down a label the directory changed. It is counted against no breaker
    budget for that reason -- a site that renames a department's worth of accounts in one afternoon has
    done nothing suspicious, and aborting a pass over it would restore the revocation cycle this exists
    to end.
    """

    user_id: str
    old_username: str
    new_username: str


#: The revocation reason each striking outcome carries once it reaches the threshold.
REVOKE_REASONS: Mapping[ProbeOutcome, str] = {
    ProbeOutcome.ABSENT: "directory_absent",
    ProbeOutcome.DISABLED: "directory_disabled",
    ProbeOutcome.UNDETERMINED: "directory_undetermined",
}

#: The outcomes that count as a READABLE answer for the hold's ``r`` (ADR 0195 rule item 5).
_READABLE = frozenset({ProbeOutcome.PRESENT, ProbeOutcome.DISABLED})

#: The closed-set slug the held audit row and alert carry (ADR 0195 rule item 9).
HOLD_REASON = "user_account_control_undetermined"


@dataclass(frozen=True)
class SessionRevocation:
    """One planned revocation. ``role_ids`` is set only for a role re-diff, and is the *target* set
    to persist before revoking (mirroring ``_complete_ad_login``'s revoke-on-role-delta)."""

    user_id: str
    username: str
    #: One of the values of :data:`REVOKE_REASONS`, or ``"roles_changed"``.
    reason: str
    role_ids: tuple[str, ...] | None = None


@dataclass(frozen=True)
class ReconcilePlan:
    """What a pass decided. Nothing here has been applied yet — see the module docstring."""

    revocations: tuple[SessionRevocation, ...] = ()
    #: Cached usernames to copy down from the directory (BACKLOG #1532). Empty on an aborted pass,
    #: like every other write this plan carries -- an abort leaves the store byte-identical.
    renames: tuple[UsernameRefresh, ...] = ()
    #: Strikes to record: ``user_id -> consecutive ABSENT, DISABLED or UNDETERMINED count``. A PRESENT
    #: probe maps to 0 (reset), and so does a HELD one (ADR 0195 rule item 7; ``held`` tells the two
    #: apart). An UNAVAILABLE probe is absent from this mapping entirely, leaving whatever strike the
    #: user already carried untouched. Populated even on a breaker abort — see :func:`plan_pass`.
    strikes: Mapping[str, int] = field(default_factory=dict)
    probed: int = 0  # principals actually probed this pass (excludes the per-pass budget remainder)
    unavailable: int = 0
    #: Non-None when the pass ABORTED and must apply nothing: the breaker tripped, or every probe in
    #: the pass failed (a whole-directory outage). The value is a closed-set operator-facing slug.
    aborted: str | None = None
    #: Outcomes to record in the caller's per-candidate record (ADR 0195 rule item 4): every probe of
    #: this pass except an UNAVAILABLE one, which leaves the prior entry in place. Populated on a
    #: breaker abort too, like ``strikes``.
    outcomes: Mapping[str, ProbeOutcome] = field(default_factory=dict)
    #: Whether this pass held its UNDETERMINED probes (:func:`hold_engaged`).
    hold: bool = False
    #: Whether the hysteresis latch is set after this pass (:func:`hold_latches`). The caller keeps
    #: it and passes it back. On a whole-directory outage nothing was judged, so it carries the
    #: caller's prior state unchanged.
    latched: bool = False
    #: ``user_id`` of every UNDETERMINED probe this pass held: no revocation, strike reset to 0.
    held: tuple[str, ...] = ()
    #: ``u``: candidates whose latest recorded outcome is UNDETERMINED, across the rotation.
    undetermined: int = 0
    #: ``r``: probes in THIS pass that read the attribute (PRESENT or DISABLED).
    readable: int = 0

    @property
    def directory_outage(self) -> bool:
        """True when the pass aborted because the directory, not the accounts, failed. The auth
        service audits this as skipped rather than aborted, and the lifespan task pages nobody for
        it. Both read this one predicate, so the audit row and the alert cannot disagree."""
        return self.aborted == "directory_unavailable"

    @property
    def judged(self) -> int:
        """The probes the mass-revoke breaker judged: every probe except the held ones (ADR 0195
        rule item 7). The breaker's decision and the ceiling an operator is told both use this."""
        return self.probed - len(self.held)


def breaker_tripped(
    *, revoke_count: int, probed: int, max_absolute: int, max_fraction: float
) -> bool:
    """Whether a pass revoking ``revoke_count`` of ``probed`` principals must be aborted.

    **BOTH** thresholds must be exceeded, deliberately. The absolute floor stops the breaker firing
    on a tiny estate where any proportion is meaningless (3 of 3 genuine offboardings is 100 %); the
    proportion stops a large estate being signed out wholesale by a bad search base. Requiring both
    means it fires only on a change that is simultaneously large in absolute terms *and* broad
    relative to the signed-in population — the signature of a misconfiguration, not of offboarding.
    """
    if revoke_count <= 0 or probed <= 0:
        return False
    return revoke_count > max_absolute and revoke_count > max_fraction * probed


def hold_engaged(*, undetermined: int, readable: int, latched: bool) -> bool:
    """Whether this pass holds its undetermined accounts (ADR 0195 rule item 6).

    ``undetermined`` is ``u``, counted across the rotation; ``readable`` is ``r``, counted in this
    pass only. **The count of one is a fixed rule, not a setting** (owner ruling 2026-09-26): an
    undetermined answer may revoke only when it is the only one the reconciler knows of AND this pass
    read the attribute on some other account. Two at once is more likely a lost read right than two
    coincidences. A lone one with nothing readable beside it cannot be told from a whole-estate wave.
    The rule has no floor; it applies at any estate size.

    ``latched`` is the hysteresis (:func:`hold_latches`): while it is set, one is still held.
    """
    if latched and undetermined > 0:
        return True
    return undetermined > 1 or (undetermined == 1 and readable == 0)


def hold_latches(*, undetermined: int, latched: bool) -> bool:
    """Whether the hysteresis latch is set after this pass (ADR 0195 rule item 6).

    **A wave sets it, and only ``u`` reaching 0 clears it.** Without it, attrition defeats the hold:
    as a wave's sessions expire, the last held account reads as a single beside readable ones and is
    revoked. So once ``u`` has exceeded one, a single is held until every held account has left the
    record.

    **A lone account held because nothing readable sat beside it does NOT set the latch.** The ADR
    says that account "starts striking once a pass also reads a readable account". Latching it would
    hold a genuine single to the absolute session cap whenever one pass happened to read nothing
    else, for example when the directory answered for that account alone.
    """
    return undetermined > 1 or (latched and undetermined > 0)


def select_candidates(
    candidates: Iterable[tuple[str, str]], *, last_probed: Mapping[str, float], budget: int
) -> list[tuple[str, str]]:
    """Choose up to ``budget`` ``(user_id, username)`` pairs, least-recently-probed first.

    Bounds the directory load of one pass. A never-probed user sorts first (``0.0``), so a newly
    signed-in principal is reconciled on the very next pass rather than waiting out a rotation; ties
    break on ``user_id`` so the order is deterministic and a pathological estate still rotates
    through everyone instead of re-probing the same slice forever.
    """
    ordered = sorted(candidates, key=lambda c: (last_probed.get(c[0], 0.0), c[0]))
    return ordered[: max(budget, 0)]


def plan_pass(
    probes: Iterable[Probe],
    *,
    prior_strikes: Mapping[str, int],
    current_roles: Mapping[str, frozenset[str]],
    target_roles: Mapping[str, frozenset[str]],
    strike_threshold: int,
    max_absolute: int,
    max_fraction: float,
    prior_outcomes: Mapping[str, ProbeOutcome] | None = None,
    latched: bool = False,
) -> ReconcilePlan:
    """Turn a pass's probe results into an all-or-nothing plan.

    ``current_roles`` / ``target_roles`` are role-id sets keyed by ``user_id``, resolved by the
    caller from the store (``get_user_role_ids``) and from the probed groups
    (``roles_for_ad_groups``). They drive the free role re-diff: because ``resolve_principal``
    already returns the group set, a *demotion* in the directory costs no extra bind.

    ``prior_outcomes`` is the caller's record of each live candidate's latest outcome, pruned to the
    current candidate set, and ``latched`` is the hysteresis latch the previous pass left
    (:func:`hold_latches`). This pass's outcomes are merged into that record BEFORE the hold is judged
    (ADR 0195 rule item 4).
    """
    probes = list(probes)
    unavailable = [p for p in probes if p.outcome is ProbeOutcome.UNAVAILABLE]

    if probes and len(unavailable) == len(probes):
        # Every probe failed: the directory, not the accounts, is what changed. Belt-and-braces on
        # top of the per-probe fail-open — this is the shape a DC outage takes, and naming it keeps
        # the operator-facing reason honest rather than reporting a silent zero-revocation pass.
        # The hold is not judged on a pass that learned nothing, so its state carries over.
        return ReconcilePlan(
            probed=len(probes),
            unavailable=len(unavailable),
            aborted="directory_unavailable",
            latched=latched,
        )

    # ADR 0195 rule items 4 to 6. An UNAVAILABLE probe leaves the prior entry in place, so a
    # directory blip on one held account does not make another look single.
    outcomes = {p.user_id: p.outcome for p in probes if p.outcome is not ProbeOutcome.UNAVAILABLE}
    record = {**(prior_outcomes or {}), **outcomes}
    undetermined = sum(1 for o in record.values() if o is ProbeOutcome.UNDETERMINED)
    readable = sum(1 for p in probes if p.outcome in _READABLE)
    hold = hold_engaged(undetermined=undetermined, readable=readable, latched=latched)

    strikes: dict[str, int] = {}
    revocations: list[SessionRevocation] = []
    held: list[str] = []
    for probe in probes:
        reason = REVOKE_REASONS.get(probe.outcome)
        if reason is None:
            continue
        if hold and probe.outcome is ProbeOutcome.UNDETERMINED:
            # Held: no revocation, and the strike count starts again from 0 (rule item 7), so an
            # account still unreadable once the hold releases needs `strike_threshold` fresh passes.
            strikes[probe.user_id] = 0
            held.append(probe.user_id)
            continue
        count = prior_strikes.get(probe.user_id, 0) + 1
        strikes[probe.user_id] = count
        if count >= strike_threshold:
            revocations.append(SessionRevocation(probe.user_id, probe.username, reason=reason))
    present = [p for p in probes if p.outcome is ProbeOutcome.PRESENT]
    for probe in present:
        strikes[probe.user_id] = 0  # a successful resolve clears the record
        target = target_roles.get(probe.user_id, frozenset())
        if target != current_roles.get(probe.user_id, frozenset()):
            # Any role DELTA revokes, matching the on-login `_complete_ad_login` behaviour: a live
            # token carries its roles, so a promotion leaves an under-privileged token just as a
            # demotion leaves an over-privileged one. Counted against the SAME breaker budget as an
            # absence — a mass role change (e.g. an emptied ad_group_role_map) is exactly as
            # suspicious as a mass disable, and must not slip past the brake.
            revocations.append(
                SessionRevocation(
                    probe.user_id,
                    probe.username,
                    reason="roles_changed",
                    role_ids=tuple(sorted(target)),
                )
            )

    plan = ReconcilePlan(
        revocations=tuple(revocations),
        # BACKLOG #1532. Planned only from a PRESENT probe -- an ABSENT or UNAVAILABLE one carries no
        # directory-reported name, so there is nothing to copy down and no evidence a rename
        # happened. A renamed account is PRESENT under the id-keyed probe; that re-keying is what
        # makes this reachable at all. Dropped again below on a breaker abort, with the revocations:
        # an aborted pass must leave the store byte-identical.
        renames=tuple(
            UsernameRefresh(p.user_id, p.username, p.directory_username)
            for p in present
            if p.directory_username is not None and p.directory_username != p.username
        ),
        strikes=strikes,
        probed=len(probes),
        unavailable=len(unavailable),
        outcomes=outcomes,
        hold=hold,
        latched=hold_latches(undetermined=undetermined, latched=latched),
        held=tuple(held),
        undetermined=undetermined,
        readable=readable,
    )
    # Held probes are left out of the breaker's denominator (rule item 7): it judges only what the
    # pass could still revoke.
    if breaker_tripped(
        revoke_count=len(revocations),
        probed=plan.judged,
        max_absolute=max_absolute,
        max_fraction=max_fraction,
    ):
        # Abort: drop every revocation, so the pass performs NO store write at all. The strikes are
        # deliberately kept — they are process-local bookkeeping, not store state, and keeping them
        # makes a standing misconfiguration trip on EVERY subsequent pass. Rolling them back instead
        # would make the breaker oscillate (accrue, trip, reset, accrue...), so the alert and its
        # audit row would flicker on and off while the estate stayed broken. The hold's fields are
        # kept too: a held pass writes its own row even when the breaker also aborts it.
        return replace(plan, revocations=(), renames=(), aborted="mass_revoke_breaker")
    return plan


def breaker_ceiling(*, probed: int, max_absolute: int, max_fraction: float) -> int:
    """The largest revocation count that would still be applied for ``probed`` principals — the
    number an operator-facing alert should quote so the threshold is legible, not a mystery."""
    return max(max_absolute, math.floor(max_fraction * probed))


def prune_ledger[V](
    ledger: dict[str, V], keep: Iterable[str], *, rank: Callable[[V], float]
) -> None:
    """Drop bookkeeping for users no longer holding a live directory session, then hard-cap what
    remains. Keeps the process-local strike, last-probed and outcome state bounded across a long
    uptime with heavy user churn. The cap drops the lowest ``rank`` first: the numeric ledgers pass
    ``float``, and the outcome record passes :func:`outcome_rank`."""
    live = set(keep)
    for user_id in [k for k in ledger if k not in live]:
        del ledger[user_id]
    if len(ledger) > LEDGER_MAX:  # pragma: no cover - pathological estate
        order = sorted(ledger, key=lambda k: rank(ledger[k]))
        for user_id in order[: len(ledger) - LEDGER_MAX]:
            del ledger[user_id]


def outcome_rank(outcome: ProbeOutcome) -> float:
    """Cap order for the outcome record: an UNDETERMINED entry is dropped last, so the cap is never
    what releases a hold."""
    return 1.0 if outcome is ProbeOutcome.UNDETERMINED else 0.0
