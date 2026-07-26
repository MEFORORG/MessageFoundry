# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Directory session reconciliation — the pure decision layer (ADR 0079 mechanism 2).

Disabling an account in Active Directory does **not** terminate its live engine session: once an
opaque token is minted the directory is never re-consulted, so the session keeps working — and keeps
refreshing — up to the flat ``[auth].session_absolute_hours`` cap. This module holds the arithmetic
that decides what a reconciliation pass would do; the I/O (LDAP probes, store writes, audit) lives in
:meth:`~messagefoundry.auth.service.AuthService.reconcile_directory_sessions`, and the timer lives in
the API lifespan. Splitting it this way keeps the two properties that matter — **fail-open** and the
**mass-revoke circuit breaker** — directly testable without a directory or a store.

Three safety properties are built in, in order of importance:

1. **Fail-OPEN on directory unavailability.** An unreachable DC yields
   :attr:`ProbeOutcome.UNAVAILABLE`, which never contributes a strike and never revokes. A
   fail-closed re-check would turn a directory blip into a total console outage during exactly the
   incident when operators need the console.
2. **Two-strike before revoking.** ``resolve_principal`` collapses *disabled*, *deleted* and *the
   search matched nothing* into a single ``None``, so one ambiguous result must not revoke.
3. **A mass-revoke circuit breaker.** A misconfigured search base, a moved OU, or a service account
   that lost read rights returns "not found" for **every** user — indistinguishable from "everyone
   was disabled". :func:`breaker_tripped` aborts such a pass wholesale rather than signing out the
   estate. This is why the pass is planned in full before anything is written: an abort must leave
   the store byte-identical, including the role re-diff.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import Enum

#: Cap on the strike/last-probed bookkeeping so a long-lived process with heavy user churn cannot
#: grow it without bound (the ``_action_step_up_grants`` / ``_new_ip_seen`` precedent). Entries are
#: pruned to the current candidate set every pass, so this only bites on a pathological estate.
LEDGER_MAX = 10_000


class ProbeOutcome(Enum):
    """What one directory probe of one principal established."""

    #: The principal resolved — the account exists and is not disabled (``_find_user`` rejects
    #: ``userAccountControl & 0x2``). Carries the current group set, so the role re-diff is free.
    PRESENT = "present"
    #: The lookup succeeded but matched nothing. **Ambiguous**: disabled, deleted, moved out of the
    #: search base, or a search base that was never right. Strikes, never revokes on its own.
    ABSENT = "absent"
    #: The directory could not be consulted (``LdapError`` — connectivity/bind/config). Contributes
    #: nothing: no strike, no revocation, no strike reset.
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class Probe:
    """One principal's probe result. ``groups`` is populated only for :attr:`ProbeOutcome.PRESENT`."""

    user_id: str
    username: str
    outcome: ProbeOutcome
    groups: frozenset[str] = frozenset()


@dataclass(frozen=True)
class SessionRevocation:
    """One planned revocation. ``role_ids`` is set only for a role re-diff, and is the *target* set
    to persist before revoking (mirroring ``_complete_ad_login``'s revoke-on-role-delta)."""

    user_id: str
    username: str
    reason: str  # "directory_absent" | "roles_changed"
    role_ids: tuple[str, ...] | None = None


@dataclass(frozen=True)
class ReconcilePlan:
    """What a pass decided. Nothing here has been applied yet — see the module docstring."""

    revocations: tuple[SessionRevocation, ...] = ()
    #: Strikes to record: ``user_id -> consecutive ABSENT count``. A PRESENT probe maps to 0 (reset);
    #: an UNAVAILABLE probe is absent from this mapping entirely, leaving whatever strike the user
    #: already carried untouched. Populated even on a breaker abort — see :func:`plan_pass`.
    strikes: Mapping[str, int] = field(default_factory=dict)
    probed: int = 0  # principals actually probed this pass (excludes the per-pass budget remainder)
    unavailable: int = 0
    #: Non-None when the pass ABORTED and must apply nothing: the breaker tripped, or every probe in
    #: the pass failed (a whole-directory outage). The value is a closed-set operator-facing slug.
    aborted: str | None = None


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
) -> ReconcilePlan:
    """Turn a pass's probe results into an all-or-nothing plan.

    ``current_roles`` / ``target_roles`` are role-id sets keyed by ``user_id``, resolved by the
    caller from the store (``get_user_role_ids``) and from the probed groups
    (``roles_for_ad_groups``). They drive the free role re-diff: because ``resolve_principal``
    already returns the group set, a *demotion* in the directory costs no extra bind.
    """
    probes = list(probes)
    absent = [p for p in probes if p.outcome is ProbeOutcome.ABSENT]
    present = [p for p in probes if p.outcome is ProbeOutcome.PRESENT]
    unavailable = [p for p in probes if p.outcome is ProbeOutcome.UNAVAILABLE]

    if probes and len(unavailable) == len(probes):
        # Every probe failed: the directory, not the accounts, is what changed. Belt-and-braces on
        # top of the per-probe fail-open — this is the shape a DC outage takes, and naming it keeps
        # the operator-facing reason honest rather than reporting a silent zero-revocation pass.
        return ReconcilePlan(
            probed=len(probes), unavailable=len(unavailable), aborted="directory_unavailable"
        )

    strikes: dict[str, int] = {}
    revocations: list[SessionRevocation] = []
    for probe in absent:
        count = prior_strikes.get(probe.user_id, 0) + 1
        strikes[probe.user_id] = count
        if count >= strike_threshold:
            revocations.append(
                SessionRevocation(probe.user_id, probe.username, reason="directory_absent")
            )
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

    if breaker_tripped(
        revoke_count=len(revocations),
        probed=len(probes),
        max_absolute=max_absolute,
        max_fraction=max_fraction,
    ):
        # Abort: drop every revocation, so the pass performs NO store write at all. The strikes are
        # deliberately kept — they are process-local bookkeeping, not store state, and keeping them
        # makes a standing misconfiguration trip on EVERY subsequent pass. Rolling them back instead
        # would make the breaker oscillate (accrue, trip, reset, accrue...), so the alert and its
        # audit row would flicker on and off while the estate stayed broken.
        return ReconcilePlan(
            strikes=strikes,
            probed=len(probes),
            unavailable=len(unavailable),
            aborted="mass_revoke_breaker",
        )

    return ReconcilePlan(
        revocations=tuple(revocations),
        strikes=strikes,
        probed=len(probes),
        unavailable=len(unavailable),
    )


def breaker_ceiling(*, probed: int, max_absolute: int, max_fraction: float) -> int:
    """The largest revocation count that would still be applied for ``probed`` principals — the
    number an operator-facing alert should quote so the threshold is legible, not a mystery."""
    return max(max_absolute, math.floor(max_fraction * probed))


def prune_ledger[V: (int, float)](ledger: dict[str, V], keep: Iterable[str]) -> None:
    """Drop bookkeeping for users no longer holding a live directory session, then hard-cap what
    remains. Keeps the process-local strike / last-probed state bounded across a long uptime with
    heavy user churn."""
    live = set(keep)
    for user_id in [k for k in ledger if k not in live]:
        del ledger[user_id]
    if len(ledger) > LEDGER_MAX:  # pragma: no cover - pathological estate
        for user_id in sorted(ledger, key=ledger.__getitem__)[: len(ledger) - LEDGER_MAX]:
            del ledger[user_id]
