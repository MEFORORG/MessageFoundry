# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Operational alert emit-points for the delivery pipeline.

The conservative ordering defaults (FIFO head-of-line blocking, a ~7 h 50 m retry cap before a row
dead-letters, stop-connection on internal error) are only *safe* if an operator is told when a lane
stalls — the cap bounds the wedge, it does not report it, so a stopped connection or a
building backlog needs a human. A full alerting/notification framework is future work
(``docs/BACKLOG.md`` item 5); until it lands, the delivery worker emits these events to an
:class:`AlertSink` whose default implementation simply **logs** them at ``WARNING``. Wiring a real
notifier later is then a matter of passing a different sink to the
:class:`~messagefoundry.pipeline.wiring_runner.RegistryRunner` — the emit-points don't change.

This module is engine-side and dependency-light (stdlib logging only), so it never pulls the API or
console into the engine.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from typing import Protocol

__all__ = [
    "INTAKE_DEPTH_REASON",
    "INTAKE_DISK_REASON",
    "AlertSink",
    "HELD_COPY_NOTE",
    "LoggingAlertSink",
    "config_changed_detail",
    "crl_expiry_detail",
    "intake_pause_detail",
]

log = logging.getLogger(__name__)

#: The two ``reason`` values of :meth:`AlertSink.intake_paused` (BACKLOG #290). Defined here so both
#: sinks and the monitor share one spelling; ``pipeline/intake_bound.py`` binds the same objects as
#: ``DEPTH_REASON`` and ``DISK_REASON``.
INTAKE_DEPTH_REASON = "staged_depth"
INTAKE_DISK_REASON = "disk_floor"


def intake_pause_detail(*, reason: str, value: int, limit: int, store_kind: str) -> str:
    """The one-line, PHI-free description of an intake pause both sinks show. It must stay true on a
    reminder raised inside the hysteresis band, where the measurement is back on the right side of
    the bound but the pause still holds, so it says what STARTED the pause. A depth read stops at
    limit + 1, so the depth line quotes no value; the disk reading is exact, so its line does."""
    if reason == INTAKE_DISK_REASON:
        return (
            f"intake paused: free space fell below the {limit} MiB floor; {value} MiB free now "
            f"({store_kind} store)"
        )
    return f"intake paused: the staged backlog went over {limit} messages ({store_kind} store)"


def config_changed_detail(
    *,
    fingerprint: str,
    previous_fingerprint: str,
    baseline_action: str,
    baseline_node: str | None,
    baseline_at: str,
) -> str:
    """The one-line description of a ``config_changed`` alert both sinks show (vault BACKLOG #2597).

    It must hold for a config that changed on purpose and for one node that diverged from the rest,
    so it states the two digests and where the older one came from and judges neither. Digests are
    cut to 12 hex characters here; the event carries them whole. No path and no git commit."""
    return (
        f"this process started with config {fingerprint[:12]}; the store's baseline is config "
        f"{previous_fingerprint[:12]} (node {baseline_node or 'unknown'}, action "
        f"{baseline_action}, time {baseline_at or 'unknown'})"
    )


#: The words that mark a ``crl_expiry`` date as a held copy's (vault BACKLOG #2319). One spelling,
#: so the log line, the notifier's ``detail`` and a test all say the same thing.
HELD_COPY_NOTE = "The date is a copy a running TLS hop holds, not the file's."


def crl_expiry_detail(*, held_copy: bool, detail: str, shared_with: tuple[str, ...]) -> str:
    """The PHI-free note both sinks add to a ``crl_expiry`` alert (vault BACKLOG #2319), or ``""``
    when no hop holds an older copy and no other row names the file.

    ``detail`` is the scan's remedy and the settings holding the copy. It leads, because the alert
    instance's reason column keeps only about the first 200 characters."""
    parts = [detail] if detail else []
    if shared_with:
        parts.append(
            f"The same file also serves {', '.join(shared_with)}; a held copy is matched by its "
            "file, so each of those rows reports it too."
        )
    if held_copy:
        parts.append(HELD_COPY_NOTE)
    return " ".join(parts)


class AlertSink(Protocol):
    """Where the delivery pipeline reports operational stalls. A real notifier (email/PagerDuty/…)
    implements this later; today the default :class:`LoggingAlertSink` just logs.

    Implementations must be cheap and non-blocking — they run inline on a delivery worker, so a slow
    sink would stall the lane it's reporting on. Never raise: an alert failure must not break delivery.
    """

    def connection_stopped(self, name: str, *, detail: str) -> None:
        """An outbound connection's delivery worker halted (``InternalErrorPolicy.STOP`` fired on an
        internal/code error). The lane is frozen until an operator intervenes (fix + reload/restart)."""
        ...

    def queue_buildup(self, name: str, *, depth: int, oldest_age_seconds: float) -> None:
        """A lane's backlog crossed a depth / oldest-in-lane-age threshold — e.g. a retry-forever
        head is blocking an outbound lane, or a slow router or transform is backing up an ingress or
        routed lane. ``name`` is the lane's connection; the stage is not passed. (Emitted by the
        buildup detector — ordering Layer 4b.)"""
        ...

    def lane_stuck(self, name: str, *, detail: str) -> None:
        """A pooled lane is retrying a **persistent T17 machinery/infra fault** at capped backoff under
        the ``retry_forever`` infra-fault policy (ADR 0070) — the head has re-faulted past the stuck
        horizon but the lane is deliberately never STOPped, so this is an **alert only, never terminal**
        (auto-resolved on the next clean head via ADR-0044 durable state when wired). Distinct from
        :meth:`connection_stopped` (the ``stop``-policy terminal) so an operator can route a "still
        retrying, look at the dependency" signal apart from a halted lane. ``name`` is the stage-lane
        label; ``detail`` is a PHI-free reason (stage + streak). Emitted by the ``StageDispatcher``."""
        ...

    def message_stall(self, name: str, *, oldest_age_seconds: float) -> None:
        """An outbound connection's **oldest undelivered message** aged past the configured
        ``StallThreshold`` (Corepoint "Max Message Stall", #50). Fired off the same oldest-pending age
        (``delivered_age``) as :meth:`queue_buildup`, but on a dedicated age-only threshold so an
        operator can page on "a message stuck > N seconds" independently of backlog *depth*. Off by
        default (deny-by-default — only fires when a threshold is configured). No PHI — the connection
        name + age only."""
        ...

    def saturation_rising(
        self, name: str, *, stage: str, depth: int, depth_start: int, growth_per_second: float
    ) -> None:
        """A lane is **becoming** overloaded (#93, ADR 0014 amendment): its pending backlog has been
        **rising sustained** across the sampling window — the DERIVATIVE signal, distinct from the
        absolute-snapshot ceilings of :meth:`queue_buildup` / :meth:`message_stall`. Sustained rising
        depth is, by conservation of the queue, ingest > drain held over the window, so a
        bursty-but-DRAINING lane (a spike that then falls back) never fires this while a genuinely
        saturating one does. ``name`` is the lane (connection) label; ``stage`` is the pipeline stage
        (``ingress``/``routed``/``outbound``) the backlog is growing in; ``depth`` is the current
        pending depth, ``depth_start`` the window's starting depth, ``growth_per_second`` the net rise
        rate. Off by default (deny-by-default — only fires when a threshold is configured). No PHI —
        the connection name + queue-shape derivative only. Emitted by the ``RegistryRunner``."""
        ...

    def log_write_failed(
        self, name: str, *, stage: str, reason: str, stopped: int | None = None
    ) -> None:
        """An **application-log sink** failed a write (BACKLOG #122, ADR 0162). ``name`` labels the sink
        (``"stdout"`` / ``"file"``); ``stage`` is ``"rolled"`` (stage 1 — the broken file was renamed
        aside and a fresh one opened, nothing stopped) or ``"unwritable"`` (stage 2 — the replacement
        failed too); ``reason`` is a ``safe_exc``-scrubbed cause; ``stopped`` is how many connections
        the fail-closed stop halted (None when nothing was stopped).

        **This alert is the operator's channel of last resort, and that is the point:** the sink it
        reports on is the one that just broke, so a log line about it may never land. The notifier's
        email/webhook transports do not go through the application log, so the page survives the failure
        the page is about. Carries the sink label, stage, reason and a count — never message content (no
        PHI), and never the record whose write failed. Dedicated rather than reusing
        :meth:`connection_stopped` so an operator can route "the engine went deaf" apart from one
        stalled lane; the stage-2 stop ALSO emits :meth:`connection_stopped` per halted connection, so
        the existing per-connection stop machinery still sees the stop and names its cause."""
        ...

    def connection_error(self, name: str, *, kind: str, detail: str | None = None) -> None:
        """An outbound connection's delivery lane went **down** — the first transport failure
        (``DeliveryError``) after the lane was healthy, edge-triggered so a retry storm fires at most
        one alert per lane per cooldown (#46, Corepoint "connection lost"). ``kind`` is the connection-
        event kind (``connection_lost``); ``detail`` is a ``safe_exc``-scrubbed reason (no PHI). A
        partner *rejection* (``NegativeAckError``) is NOT a connection error and never fires this."""
        ...

    def storage_threshold(self, path: str, *, size_bytes: int, limit_bytes: int) -> None:
        """The message store grew past the configured ``[retention] max_db_mb`` advisory threshold.
        Emitted by the :class:`~messagefoundry.pipeline.retention.RetentionRunner` once per pass while
        over the limit; ``path`` identifies the DB, never any message content (no PHI)."""
        ...

    def intake_paused(
        self, name: str, *, reason: str, value: int, limit: int, store_kind: str
    ) -> None:
        """The engine PAUSED intake on one of its two bounds (BACKLOG #290, ASVS 15.2.2). The
        ingest-side signal: :meth:`queue_buildup` keys on one lane, while this one says every source
        that honours the pause has stopped reading.

        ``reason`` is ``staged_depth`` (the staged backlog, ingress plus routed rows in the one
        store, went over ``[inbound].max_staged_depth``; ``value`` and ``limit`` are message counts,
        and ``value`` is capped at one past ``limit`` because the read only asks "over or not") or
        ``disk_floor`` (free space on the SQLite store's volume fell below
        ``[retention].min_free_disk_mb``; ``value`` and ``limit`` are MiB). ``store_kind`` is the
        store backend (``sqlite``, ``sqlserver`` or ``postgres``). ``name`` is ``intake:<reason>``,
        so each bound is its own instance and a drained backlog cannot resolve a low-disk pause. It
        names no node: both bounds measure the one shared store, and a cluster node id changes on
        every restart, so a node-keyed instance could never be resolved by the next start. It is not
        a connection-scoped event, so no rule's ``control_action`` fires on it (BACKLOG #1898).
        Its colon also keeps ``name`` outside the connection-name grammar, which guards only the
        default target, never a rule's ``control_target``. Carries counts and sizes only: no
        message content, no PHI. Raised when a pause
        starts and again about every five minutes while it holds, as :meth:`queue_buildup` is, so a
        notifier's re-alert, escalation and suspend logic see a condition that persists. Emitted by
        :class:`~messagefoundry.pipeline.intake_bound.IntakeBoundMonitor`;
        :meth:`intake_resumed` is its auto-resolving inverse."""
        ...

    def intake_resumed(
        self, name: str, *, reason: str, value: int, limit: int, store_kind: str
    ) -> None:
        """The INVERSE of :meth:`intake_paused`: the bound named by ``reason`` cleared its resume
        line. Emits **no** notification (a recovery needs no page); it exists so durable alert-state
        (ADR 0044) **auto-resolves** the open ``intake_paused`` instance for the same ``name``. Also
        raised once per start for a bound measured clear of its resume line, or one that is OFF
        (then ``value`` and ``limit`` are 0), so a pause left open by an engine that stopped
        while paused is cleared by the next clean start, as :meth:`store_privilege_clean` does. Same
        fields as :meth:`intake_paused`. No PHI."""
        ...

    def cert_expiry(self, name: str, *, path: str, not_after: str, days_remaining: int) -> None:
        """A served TLS certificate is expired or within the configured warn window. ``name`` labels
        which cert (``"api"`` or the connection name); ``path`` is the PEM file; ``not_after`` is the
        ISO expiry; ``days_remaining`` is negative once expired. No key material is read or logged.
        Emitted by the :class:`~messagefoundry.pipeline.cert_expiry.CertExpiryRunner`."""
        ...

    def crl_expiry(
        self,
        name: str,
        *,
        path: str,
        not_after: str,
        days_remaining: int,
        held_copy: bool = False,
        detail: str = "",
        shared_with: tuple[str, ...] = (),
    ) -> None:
        """A configured CRL is expired or within the warn window (BACKLOG #1005). ``name`` labels
        the inbound connection, or the setting that names the CRL, such as ``"tls.crl_file"`` for
        the CRLs on outbound hops (BACKLOG #299); ``path`` is the PEM; ``not_after`` is the ISO
        ``nextUpdate``; ``days_remaining`` is negative once expired.

        **Whose date it is (vault BACKLOG #2319).** ``held_copy`` is True when ``not_after`` is not
        the file's: it is the ``nextUpdate`` of an older copy that a running TLS hop still holds,
        which lapses before the file does. Replacing the file again does not move that date; the
        reload has to apply the file to the hop, or a restart has to rebuild it. ``detail`` says what
        to do, in the words the scan logs, then which settings hold the older copy; it is set
        whenever a hop holds a copy that differs from the file, even one that is not the date. ``shared_with``
        names the other monitored settings or connections whose rows name the same file. A held
        copy is matched by its file, not its hop, so it is reported under every row naming that
        file, and ``detail`` says which hop holds it. All three carry config metadata only: no key
        material and no message content.

        **SEPARATE FROM :meth:`cert_expiry` BECAUSE THE REMEDY AND THE BLAST RADIUS DIFFER.** An
        expiring server certificate degrades one identity and is fixed by reissuing it. An expired
        CRL makes OpenSSL fail EVERY handshake it verifies -- not merely those of revoked
        certificates. A listener then refuses every client, and an outbound hop cannot connect to
        its peer. So an unrefreshed CRL is a total interface outage, and the fix is a PKI refresh
        rather than a reissue. Emitting both down one method would give an operator one string for
        two causes with opposite remedies."""
        ...

    def secret_rotation_due(
        self,
        name: str,
        *,
        class_id: str,
        last_rotated: str,
        days_overdue: int,
        enforced: bool = False,
    ) -> None:
        """A tracked long-lived secret is overdue (or within the warn window) for rotation (#195b, ADR
        0019 §5; widened to keyed-MAC-fingerprinted classes in ASVS 13.3.4 / BACKLOG #282). ``name`` labels
        the secret (e.g. ``"store data-encryption key"``); ``class_id`` is the secret's config/env
        **identifier** (e.g. ``"MEFOR_STORE_ENCRYPTION_KEY"``); ``last_rotated`` is the ISO date it was
        last rotated (operator-configured, or the engine's auto-detected tracked/rotation stamp);
        ``days_overdue`` is positive once past the max age, negative while still within the warn window.
        ``enforced`` is the ASVS-13.3.4 ENFORCE escalation: ``True`` when the DEK is past ``max_age +
        grace`` under ``[security].enforcement=ENFORCE`` at restart, so an operator can triage it at a
        higher severity than a routine reminder. **No key material** is ever read or logged — only the
        identifier + rotation dates + a one-way keyed-MAC fingerprint (no value, no PHI). Emitted by the
        :class:`~messagefoundry.pipeline.secret_rotation.SecretRotationRunner`. Dedicated (not reusing
        :meth:`cert_expiry`) so an operator can route a rotation reminder apart from a cert-expiry alert."""
        ...

    def initial_credential_expiring(
        self, name: str, *, expires_at: str, hours_remaining: int
    ) -> None:
        """An **admin-issued temporary password** (a create-user or reset credential, still
        ``must_change_password``) is UNCLAIMED and near the instant the login gate stops accepting it
        (ASVS 6.4.5, BACKLOG #1141). ``name`` is ``user:<holder's username>``, so the throttle and
        the alert instance key per account; ``expires_at`` is the ISO instant; ``hours_remaining`` is
        the whole hours left (``0`` in the final hour).

        The prefix does not hide the event from rules. ``AlertRule.connection`` defaults to ``"*"``,
        so a catch-all rule matches it. Where a catch-all rule is the first match, its ``mute`` or
        ``transports=[]`` silences this reminder. No ``control_action`` fires on it, since it is not
        a connection-scoped event (BACKLOG #1898). Rules apply only where
        ``[alerts]`` has a transport; without one, :class:`LoggingAlertSink` logs every event.

        This is the OPERATOR's copy. The holder and the issuing administrator each get their own
        security notice at their notification address (BACKLOG #2007), where one can be found; this
        alert reaches the operator whether or not they do. If the credential lapses unclaimed, reset
        it again. The alert does not resolve itself when the holder claims it, so check the account
        before a reset. Carries **only** the
        username, the deadline and the hours: never the password, and no message content (no PHI).
        Emitted once per credential per process by the API-lifespan reminder task."""
        ...

    def approval_stale_requester(self, approval_id: str, *, operation: str, reason: str) -> None:
        """A second approver tried to release a held dual-control request, and the release was
        REFUSED because the requester no longer holds the authority it needs (ASVS 8.3.2). ``reason``
        is a closed-set slug: ``requester_missing``, ``requester_disabled``,
        ``requester_lacks_permission``, ``requester_out_of_scope`` or ``requester_unverifiable``.
        Keyed on ``approval_id`` so each refused request pages on its own. Carries the id, the
        operation key and the slug only: no username, no params, no message content (no PHI). The
        ``approval.stale_requester`` audit row is the durable record; this is the page. Emitted by
        :class:`~messagefoundry.api.approvals.ApprovalGate`."""
        ...

    def approval_too_early(self, name: str, *, operation: str) -> None:
        """A second approver tried to release a held dual-control request younger than
        ``[approvals].min_dwell_seconds``, and the release was REFUSED (ASVS 2.4.2, BACKLOG #287). A
        release that fast is quicker than the published human-timing floor, so it is worth a look:
        it may be a script. Not raised when the request reads as younger than zero, since that is a
        clock behind the requester's and not a fast approver.

        ``name`` is ``approval:<approval id>``, the key :meth:`approval_approver_provenance` uses. It
        is not a connection-scoped event, so no rule's ``control_action`` fires on it (BACKLOG
        #1898). Its colon also keeps ``name`` outside the connection-name grammar, which guards
        only the default target, never a rule's ``control_target``.
        The prefix does not hide the event from rules: a catch-all rule still matches it for
        severity, routing and mute. Repeated early tries on one request fold into one instance.
        Nothing resolves the instance when the request is later decided, so an operator resolves
        it. Carries the key, the
        operation key and a fixed reason string: no username, no params, no PHI. The
        ``approval.too_early`` audit row is the durable record. Emitted by
        :class:`~messagefoundry.api.approvals.ApprovalGate`."""
        ...

    def approval_approver_provenance(
        self, name: str, *, operation: str, changed: tuple[str, ...]
    ) -> None:
        """A held dual-control request was RELEASED by an approver whose account changed after the
        request was made (BACKLOG #315; why, on ``ApprovalGate._approver_changes``). The release
        went ahead: this flags it and refuses nothing. ``name`` is ``approval:<approval id>``. It is
        not a connection-scoped event, so no rule's ``control_action`` fires on it (BACKLOG #1898),
        and the colon keeps ``name`` outside the connection-name grammar, which guards only the
        default target, never a rule's ``control_target``.
        ``changed`` holds one or more of
        ``account_created``, ``password_changed`` and ``totp_enrolled``. Carries the key, the
        operation key and the slugs only: no username, no params, no PHI. The
        ``approval.approver_provenance`` audit row is the durable record. Emitted by
        :class:`~messagefoundry.api.approvals.ApprovalGate`."""
        ...

    def administrator_granted(self, name: str, *, via: str, granted_by: str) -> None:
        """The built-in Administrator role was granted through the console API (BACKLOG #315). Every
        approver is an Administrator, so this is how a second approver gets minted. ``via`` is
        ``account_created`` or ``roles_changed`` with ``name`` = ``user:<username>``, or
        ``ad_group_map`` with ``name`` = ``ad-group:<group>`` when a group newly maps to the role.
        A directory sign-in whose role sync newly grants the role (vault BACKLOG #2610) raises it
        with ``name`` = ``user:<username>`` and ``via`` = ``directory_sign_in_negotiate``,
        ``directory_sign_in_sso`` or ``directory_sign_in_oidc``, naming the route.
        Both keys are outside the connection-name grammar for the same reason as
        :meth:`approval_approver_provenance`. ``granted_by`` is the acting administrator's username,
        or ``<directory>`` on a directory sign-in, where no administrator acted.
        No PHI. Emitted by the API's user-administration and directory sign-in routes, never from
        ``auth/``."""
        ...

    def ad_reconcile_aborted(self, name: str, *, reason: str, probed: int, detail: str) -> None:
        """A directory reconciliation pass revoked nothing for some or all signed-in accounts and
        needs an operator (ADR 0079 mechanism 2). Either the mass-revoke circuit breaker tripped
        (``reason`` ``mass_revoke_breaker``), so the pass applied NOTHING, the same event as the
        ``auth.ad_reconcile_aborted`` audit row; or the directory answered one or more probes with a
        referral (``directory_referral``, BACKLOG #2538, the ``auth.ad_reconcile_referred`` row),
        which leaves the referred accounts unjudged and may sit beside revocations the pass applied.
        The type's name predates the second case. Read ``reason`` before naming the cause.

        ``name`` labels the source: ``"directory-reconciler"`` for the breaker, and
        ``"directory-reconciler-referral"`` for a referral, so each is its own instance and
        throttle. ``reason`` is one of those two closed-set slugs. ``probed`` is how many
        principals the pass probed. ``detail`` is the operator-facing explanation the auth service
        latches. No PHI. Emitted by the API-lifespan
        reconciler task, never from ``auth/``. A whole-directory outage is NOT this event: it is
        audited as ``auth.ad_reconcile_skipped`` and pages nothing, because the accounts are fine."""
        ...

    def ad_reconcile_held(self, name: str, *, reason: str, undetermined: int, detail: str) -> None:
        """A directory reconciliation pass held the sessions of accounts whose ``userAccountControl``
        it could not read, and revoked none of them (ADR 0195). The same event as the
        ``auth.ad_reconcile_held`` audit row, raised on every pass while the hold is engaged,
        including a pass the mass-revoke breaker also aborts. ``name`` labels the source
        (``"directory-reconciler"``), so this type throttles apart from ``ad_reconcile_aborted``;
        ``reason`` is the closed-set slug ``user_account_control_undetermined``; ``undetermined`` is
        how many signed-in accounts read undetermined; ``detail`` is the operator-facing explanation
        the auth service latches. No PHI. Emitted by the API-lifespan reconciler task, never from
        ``auth/``. :meth:`ad_reconcile_hold_released` is its auto-resolving inverse."""
        ...

    def ad_reconcile_breaker_cleared(self, name: str) -> None:
        """The INVERSE of :meth:`ad_reconcile_aborted` (BACKLOG #2136): a pass that is evidence the
        mass-revoke breaker is not tripped, or, under the referral's source label, that no referral
        stands (BACKLOG #2538), as the auth service judges it
        (``AuthService._mark_reconcile_clears`` states the test). Emits **no** notification; when
        alert-state is wired (ADR 0044) it auto-resolves the open ``ad_reconcile_aborted`` instance
        for the same ``name``: ``"directory-reconciler"`` for the breaker's instance, and
        ``"directory-reconciler-referral"`` for the referral's. Raised on every such pass, except where
        ``api/app.py::_is_sole_reconciler`` says another reconciler may run, at least on a
        ``[cluster]`` node or in an engine that runs more than one engine shard
        (``api/app.py::_without_clears`` says why), and while the open instance is one an earlier
        run left open (``api/app.py::_without_inherited_clears``). The sole-reconciler gate does
        not see every engine on the store; ``AuthService._mark_reconcile_clears`` names at least
        the cases that can still resolve falsely. No PHI. Emitted by the API-lifespan reconciler task, never from
        ``auth/``."""
        ...

    def ad_reconcile_hold_released(self, name: str) -> None:
        """The INVERSE of :meth:`ad_reconcile_held` (BACKLOG #2136): a pass that is evidence no
        undetermined-wave hold stands, as the auth service judges it
        (``AuthService._mark_reconcile_clears`` states the test, which is not the breaker's).
        Emits **no** notification; when alert-state is wired
        (ADR 0044) it auto-resolves the open ``ad_reconcile_held`` instance for the same ``name``
        (``"directory-reconciler"``). Raised as :meth:`ad_reconcile_breaker_cleared` is. No PHI.
        Emitted by the API-lifespan reconciler task, never from ``auth/``."""
        ...

    def ad_session_revoked(self, name: str, *, reason: str) -> None:
        """A directory reconciliation pass revoked a directory principal's live sessions, because the
        account left the directory, its mapped roles changed, or the directory would withdraw or
        narrow its channel scope (ADR 0079 mechanism 2, ADR 0198). The same event as the
        ``auth.ad_session_revoked`` audit row. ``name`` is the account's username, so each revoked
        principal pages on its own; ``reason`` is ``directory_absent``, ``directory_disabled``,
        ``directory_undetermined``, ``roles_changed`` or ``scope_changed``.
        No PHI. Emitted by the API-lifespan reconciler task, never from ``auth/``."""
        ...

    def gcm_invocations(self, name: str, *, key_id: str, invocations: int, ceiling: int) -> None:
        """The active store data-encryption key has crossed the AES-GCM soft invocation threshold
        (2**31 of the 2**32 birthday ceiling) on its PERSISTED, fleet-wide cumulative count (ASVS
        11.3.4). ``name`` labels the key's role (``"store data-encryption key"``); ``key_id`` is the
        one-way SHA-256 fingerprint already embedded in every ciphertext marker — **never key material**;
        ``invocations`` is the cumulative count and ``ceiling`` the fail-closed limit. Carries no PHI and
        no key bytes. Emitted by the
        :class:`~messagefoundry.pipeline.gcm_invocations.GcmInvocationRunner`. Dedicated (not reusing
        :meth:`secret_rotation_due`) because this is a MEASURED exhaustion signal with a hard stop behind
        it, not a calendar reminder — crossing the ceiling refuses further encrypts, so it warrants its
        own routing/severity."""
        ...

    def integrity_drift(self, name: str, *, reason: str, drift_count: int) -> None:
        """Startup self-attestation found loaded engine module(s) that do not match the installed
        wheel ``RECORD`` baseline — a runtime in-place tamper tripwire (ADR 0041 D3, #54). ``name``
        labels the source; startup attestation uses at least ``"engine-integrity"``, and
        :mod:`messagefoundry.integrity` defines its other subjects, including the web console's
        (BACKLOG #1802). ``reason`` is a PHI-free summary string;
        ``drift_count`` is how many module files drifted. Carries no file content (no PHI, nothing
        sensitive). Emitted by :func:`~messagefoundry.integrity.run_startup_attestation`. Dedicated
        rather than reusing :meth:`connection_stopped` so an operator can route/triage a tamper signal
        independently of a stalled delivery lane."""
        ...

    def update_available(self, name: str, *, current_version: str, pinned_version: str) -> None:
        """A newer MessageFoundry version is pinned/installed than is running (#30, ADR 0026). ``name``
        labels the package (``"messagefoundry"``); ``current_version`` is the running
        :data:`messagefoundry.__version__`; ``pinned_version`` is what the install pins. Carries **only**
        version strings — no PHI, no dependency list, no host data. Emitted by
        :class:`~messagefoundry.pipeline.update_check.UpdateCheckRunner` (the no-network local diff)."""
        ...

    def connection_restored(self, name: str) -> None:
        """An outbound lane recovered — the **inverse** of :meth:`connection_error` (``connection_lost``).
        Emits **no** notification (a recovery needs no page); it exists so durable alert-state (ADR 0044,
        #56) can **auto-resolve** the matching open ``connection_error`` instance when wired. The default
        :class:`LoggingAlertSink` and any state-less sink treat it as a no-op. ``name`` is the connection
        label only (no PHI)."""
        ...

    def backup_failed(self, name: str, *, kind: str, detail: str | None = None) -> None:
        """A scheduled or on-demand DR backup failed (ADR 0049, #60) — the snapshot, encrypt, write, or
        restore-verify step. ``name`` labels the source (``"dr_backup"``); ``kind`` is the failing phase
        (``snapshot``/``encrypt``/``write``/``verify``/``destination``/``space``, the last when the
        run would not fit on its staging or destination volume). One kind is not a failure: ``cleanup``
        is a good run whose plaintext staging could not be cleared, and it is raised under its own
        subject, ``"dr_backup:staging"``, so it never shares a failed backup's throttle or instance
        (BACKLOG #1174). ``detail`` is a PHI-free,
        ``safe_exc``-scrubbed error **class/reason** — never a message body or key material. Dedicated
        (not reusing :meth:`storage_threshold`) so an operator can route/triage a backup failure
        independently of a store-size alert. Emitted by the
        :class:`~messagefoundry.pipeline.dr_backup.BackupRunner` (and the ``backup`` CLI), so a silent
        backup failure surfaces as an alert + the ``dr_backup`` ERROR disposition, not as a missing
        archive discovered during a disaster."""
        ...

    def store_privilege_warning(
        self, name: str, *, finding: str, excess_count: int, detail: str
    ) -> None:
        """The store privilege preflight took its WARN arm at start (BACKLOG #305, ASVS 13.2.2):
        ``finding`` is ``"over_granted"`` (the store principal holds ``excess_count`` privilege(s)
        beyond the documented grant) or ``"unobservable"`` (the probe could not read the principal,
        which is not a clean result; ``excess_count`` is then 0 and means nothing). ``name`` is the
        subject, ``store:<principal>@<database>``, or ``store`` when the probe named no principal. ``detail`` is the
        preflight's summary line: principal, database and role NAMES only, already redacted -- no
        secret, no message content. Fired before any refusal, so a refused start still pages, and on an
        over-grant the ADR 0199 opt-out accepts, which quiets nothing. Emitted by
        :func:`~messagefoundry.store.privilege.run_store_privilege_preflight`."""
        ...

    def store_privilege_clean(self, name: str) -> None:
        """The INVERSE of :meth:`store_privilege_warning`: a start whose preflight OBSERVED a clean
        store principal. No page; when alert-state is wired (ADR 0044) it auto-resolves the open
        warning for the same subject, so a fixed grant clears the dashboard."""
        ...

    def config_changed(
        self,
        name: str,
        *,
        fingerprint: str,
        previous_fingerprint: str,
        node: str | None,
        shard: str | None,
        baseline_action: str,
        baseline_actor: str | None,
        baseline_at: str,
        baseline_node: str | None,
    ) -> None:
        """This process started with a config whose ADR 0041 D1 fingerprint differs from the store's
        baseline (vault BACKLOG #2597). The baseline is the newest usable ``config_loaded``,
        ``config_reload`` or ``connection_flag_set`` audit row from any node or engine shard, since
        every one of them shares one config directory; a row whose digest its process never checked
        is passed over, so the baseline can be older than the newest row. So an edit applied first by ``POST
        /config/reload`` and then restarted does not fire it, and an edit that only a restart picked
        up does, by design: nothing else separates that deploy from an unrecorded edit.

        ``name`` is ``config:<first 12 hex of fingerprint>``, so each distinct config is its own
        instance to acknowledge, and nothing resolves it. ``fingerprint`` and
        ``previous_fingerprint`` are the two whole digests; ``node`` and ``shard`` are this
        process's; ``baseline_action``, ``baseline_actor``, ``baseline_at`` (ISO-8601 UTC) and
        ``baseline_node`` describe the row the older digest came from. Never a path, a git commit
        or message content (no PHI). It is not a connection-scoped event, so no rule's
        ``control_action`` fires on it (BACKLOG #1898). Raised once per start at most, never on a
        fresh store, a baseline without a digest, or one taken under another fingerprint scheme."""
        ...

    def leadership_acquired(self, node: str, *, role: str, epoch: int | None = None) -> None:
        """A node went **non-leader → leader** (BACKLOG #145) — an active-passive HA failover / the
        initial election. The page-worthy edge the failover blind spot hid: an operator sees leadership
        *move* without polling ``/cluster/status``. ``node`` is the cluster node id (also the throttle
        key); ``role`` is ``"leader"``; ``epoch`` is the held H1 leader epoch. Carries **only**
        node/role/epoch — cluster-topology facts, never message content (no PHI). Emitted by the cluster
        coordinators (``DbCoordinator`` / ``SqlServerCoordinator``); :meth:`leadership_lost` is its
        auto-resolving inverse."""
        ...

    def leadership_lost(self, node: str, *, role: str, reason: str) -> None:
        """A node **lost / self-fenced / cleanly released** leadership (BACKLOG #145) — the **inverse** of
        :meth:`leadership_acquired`. Emits **no** notification (a step-down needs no page); it exists so
        durable alert-state (ADR 0044) **auto-resolves** the matching open ``leadership_acquired`` instance
        (the open set then tracks the current leaders). ``node`` is the node id; ``role`` is ``"follower"``;
        ``reason`` is a PHI-free cause (``"lease taken or expired"`` / ``"self-fenced"`` / ``"released"``).
        The default :class:`LoggingAlertSink` logs it; a state-less sink treats it as a no-op."""
        ...

    def dr_activated(self, node: str, *, role: str) -> None:
        """A third-tier DR standby was **promoted** (BACKLOG #145, ADR 0048) — the primary is down and this
        box is now serving the priority feeds. Page-worthy. ``node`` is the DR box's host label (also the
        throttle key); ``role`` is ``"dr_standby"``. Carries **only** node/role (no PHI). Emitted by
        :class:`~messagefoundry.pipeline.dr.DrCoordinator` on ``activate``; :meth:`dr_released` is its
        auto-resolving inverse."""
        ...

    def dr_released(self, node: str, *, role: str) -> None:
        """A DR box **failed back** to the recovered primary (BACKLOG #145, ADR 0048) — the **inverse** of
        :meth:`dr_activated`. Emits **no** notification (a fail-back needs no page); it **auto-resolves**
        the matching open ``dr_activated`` instance (ADR 0044). ``node`` is the DR box label; ``role`` is
        ``"primary"`` (leadership handed back). No PHI."""
        ...


class LoggingAlertSink:
    """Default :class:`AlertSink`: log each event at ``WARNING``. No PHI — only the connection name
    and queue shape are recorded, never a message body."""

    def connection_stopped(self, name: str, *, detail: str) -> None:
        log.warning(
            "ALERT connection_stopped: outbound %r halted on internal error: %s", name, detail
        )

    def queue_buildup(self, name: str, *, depth: int, oldest_age_seconds: float) -> None:
        log.warning(
            # "lane", not "outbound": ingress and routed lanes fire this too (BACKLOG #290).
            "ALERT queue_buildup: lane %r backlog depth=%d oldest=%.0fs",
            name,
            depth,
            oldest_age_seconds,
        )

    def lane_stuck(self, name: str, *, detail: str) -> None:
        log.warning(
            "ALERT lane_stuck: lane %r retrying a persistent infra fault (retry_forever): %s",
            name,
            detail,
        )

    def message_stall(self, name: str, *, oldest_age_seconds: float) -> None:
        log.warning(
            "ALERT message_stall: outbound %r oldest undelivered message stalled %.0fs",
            name,
            oldest_age_seconds,
        )

    def saturation_rising(
        self, name: str, *, stage: str, depth: int, depth_start: int, growth_per_second: float
    ) -> None:
        log.warning(
            "ALERT saturation: lane %r (%s) backlog RISING — depth %d->%d (+%.2f/s); ingest exceeding drain",
            name,
            stage,
            depth_start,
            depth,
            growth_per_second,
        )

    def connection_error(self, name: str, *, kind: str, detail: str | None = None) -> None:
        log.warning("ALERT connection_error: outbound %r %s: %s", name, kind, detail or "")

    def log_write_failed(
        self, name: str, *, stage: str, reason: str, stopped: int | None = None
    ) -> None:
        # The honest caveat, stated once where it lives: this default sink LOGS, and the thing that
        # just failed is a log sink. If the failure is process-wide this line goes nowhere — which is
        # exactly why the guard also writes a PHI-free stderr line of last resort, and why an operator
        # who wants to be told routes this event to the email/webhook notifier instead.
        log.warning(
            "ALERT log_write_failed: application-log sink %r %s (%s)%s",
            name,
            stage,
            reason,
            "" if stopped is None else f"; {stopped} connection(s) stopped",
        )

    def storage_threshold(self, path: str, *, size_bytes: int, limit_bytes: int) -> None:
        log.warning(
            "ALERT storage_threshold: store %r is %.1f MB, over the %.1f MB retention limit",
            path,
            size_bytes / 1_000_000,
            limit_bytes / 1_000_000,
        )

    def intake_paused(
        self, name: str, *, reason: str, value: int, limit: int, store_kind: str
    ) -> None:
        log.warning(
            "ALERT intake_paused: %r %s",
            name,
            intake_pause_detail(reason=reason, value=value, limit=limit, store_kind=store_kind),
        )

    def intake_resumed(
        self, name: str, *, reason: str, value: int, limit: int, store_kind: str
    ) -> None:
        # The inverse (auto-resolve) event; no page, so DEBUG: the monitor already logged at INFO.
        log.debug(
            "ALERT intake_resumed: %r clear on the %s store (%s: %d against a limit of %d)",
            name,
            store_kind,
            reason,
            value,
            limit,
        )

    def cert_expiry(self, name: str, *, path: str, not_after: str, days_remaining: int) -> None:
        if days_remaining < 0:
            log.warning(
                "ALERT cert_expiry: %r certificate (%s) EXPIRED %d day(s) ago (not_after=%s)",
                name,
                path,
                -days_remaining,
                not_after,
            )
        else:
            log.warning(
                "ALERT cert_expiry: %r certificate (%s) expires in %d day(s) (not_after=%s)",
                name,
                path,
                days_remaining,
                not_after,
            )

    def crl_expiry(
        self,
        name: str,
        *,
        path: str,
        not_after: str,
        days_remaining: int,
        held_copy: bool = False,
        detail: str = "",
        shared_with: tuple[str, ...] = (),
    ) -> None:
        # Vault BACKLOG #2319: say whose date this is before the line that gives it, so the line
        # below is not read as the file's. At the same level, since a held copy's lapse is the
        # outage just as the file's would be.
        if note := crl_expiry_detail(held_copy=held_copy, detail=detail, shared_with=shared_with):
            log.log(
                logging.ERROR if days_remaining < 0 else logging.WARNING,
                "crl_expiry: %r CRL %s: %s",
                name,
                path,
                note,
            )
        # An EXPIRED crl fails every handshake it verifies, so it is an ERROR rather than a warning:
        # the hop is effectively down, not merely approaching a deadline (BACKLOG #1005). The wording
        # names no direction, because the same CRL may guard a listener or an outbound hop (#299):
        # a listener refuses every client, and an outbound hop cannot connect to its peer.
        # A hop reads its CRL when it builds its TLS context and keeps that copy. The reload pass
        # (pipeline/crl_reload.py) applies a replaced file to a running hop within about a minute,
        # and the scan judges the copies live contexts hold as well as the file (BACKLOG #299). So a
        # copy the reload refused keeps this alert up, and the scan's own warning says why.
        if days_remaining < 0:
            log.error(
                "crl_expiry: %r CRL expired at %s (%d day(s) ago) — every TLS handshake it "
                "verifies fails (a listener refuses every client; an outbound hop cannot connect to "
                "its peer). Replace the file, and restart the engine if the scan still reports a running "
                "hop holding the old copy: %s",
                name,
                not_after,
                -days_remaining,
                path,
            )
        else:
            log.warning(
                "crl_expiry: %r CRL expires at %s (%d day(s) left). Replace the file before then, "
                "or every TLS handshake it verifies will fail, and restart the engine if the scan "
                "still reports a running hop holding the old copy: %s",
                name,
                not_after,
                days_remaining,
                path,
            )

    def secret_rotation_due(
        self,
        name: str,
        *,
        class_id: str,
        last_rotated: str,
        days_overdue: int,
        enforced: bool = False,
    ) -> None:
        if enforced:
            # ASVS 13.3.4 ENFORCE escalation: past max_age + grace under strict enforcement. Logged at
            # ERROR (vs the routine WARNING) so it is triaged at a higher severity.
            log.error(
                "ALERT secret_rotation: %r (%s) is OVERDUE for rotation by %d day(s) past the enforced "
                "grace (last_rotated=%s) — [security].enforcement=ENFORCE",
                name,
                class_id,
                days_overdue,
                last_rotated,
            )
        elif days_overdue > 0:
            log.warning(
                "ALERT secret_rotation: %r (%s) is OVERDUE for rotation by %d day(s) "
                "(last_rotated=%s)",
                name,
                class_id,
                days_overdue,
                last_rotated,
            )
        else:
            log.warning(
                "ALERT secret_rotation: %r (%s) is due for rotation in %d day(s) (last_rotated=%s)",
                name,
                class_id,
                -days_overdue,
                last_rotated,
            )

    def initial_credential_expiring(
        self, name: str, *, expires_at: str, hours_remaining: int
    ) -> None:
        log.warning(
            "ALERT initial_credential_expiring: the temporary password issued to %r is UNCLAIMED and "
            "stops working in %d hour(s) (expires %s) -- the holder must sign in and change it, or "
            "an administrator must reset it again after it lapses",
            name,
            hours_remaining,
            expires_at,
        )

    def approval_stale_requester(self, approval_id: str, *, operation: str, reason: str) -> None:
        log.warning(
            "ALERT approval_stale_requester: release of %s request %r refused (%s)",
            operation,
            approval_id,
            reason,
        )

    def approval_too_early(self, name: str, *, operation: str) -> None:
        log.warning(
            "ALERT approval_too_early: release of %s request %r refused, it was younger than the "
            "minimum dwell",
            operation,
            name,
        )

    def approval_approver_provenance(
        self, name: str, *, operation: str, changed: tuple[str, ...]
    ) -> None:
        log.warning(
            "ALERT approval_approver_provenance: %s request %r was released by an approver whose "
            "account changed after the request (%s)",
            operation,
            name,
            ", ".join(changed),
        )

    def administrator_granted(self, name: str, *, via: str, granted_by: str) -> None:
        log.warning(
            "ALERT administrator_granted: %r was given the Administrator role (%s) by %r",
            name,
            via,
            granted_by,
        )

    def ad_reconcile_aborted(self, name: str, *, reason: str, probed: int, detail: str) -> None:
        log.warning(
            "ALERT ad_reconcile_aborted: %r left accounts unrevoked in a pass of %d principal(s) "
            "(%s): %s",
            name,
            probed,
            reason,
            detail,
        )

    def ad_reconcile_held(self, name: str, *, reason: str, undetermined: int, detail: str) -> None:
        log.warning(
            "ALERT ad_reconcile_held: %r is holding %d undetermined account(s) (%s): %s",
            name,
            undetermined,
            reason,
            detail,
        )

    def ad_reconcile_breaker_cleared(self, name: str) -> None:
        # The inverse (auto-resolve) event, raised on every clear pass; no page, so DEBUG.
        # The referral's source label raises it too, once no referral stands (BACKLOG #2538).
        log.debug("ALERT ad_reconcile_breaker_cleared: %r found its condition clear", name)

    def ad_reconcile_hold_released(self, name: str) -> None:
        # The inverse (auto-resolve) event, raised on every clear pass; no page, so DEBUG. A hold
        # the auth service releases while its message is set is logged there at WARNING.
        log.debug("ALERT ad_reconcile_hold_released: %r found no hold standing", name)

    def ad_session_revoked(self, name: str, *, reason: str) -> None:
        log.warning(
            "ALERT ad_session_revoked: directory principal %r had its sessions revoked (%s)",
            name,
            reason,
        )

    def gcm_invocations(self, name: str, *, key_id: str, invocations: int, ceiling: int) -> None:
        log.warning(
            "ALERT gcm_invocations: %r (key_id=%s) has encrypted %d value(s), %.1f%% of the %d "
            "fail-closed AES-GCM ceiling — rotate the key (`messagefoundry rotate-key`) before it stops",
            name,
            key_id,
            invocations,
            100.0 * invocations / ceiling if ceiling else 0.0,
            ceiling,
        )

    def integrity_drift(self, name: str, *, reason: str, drift_count: int) -> None:
        log.warning(
            # One channel, several subjects: engine-module attestation, the audit chain and the
            # store cipher (#1169) all report here, so the line names the finding generically.
            "ALERT integrity_drift: %r reported %d integrity finding(s): %s",
            name,
            drift_count,
            reason,
        )

    def update_available(self, name: str, *, current_version: str, pinned_version: str) -> None:
        log.warning(
            "ALERT update_available: %r running %s but %s is pinned/installed — update available",
            name,
            current_version,
            pinned_version,
        )

    def connection_restored(self, name: str) -> None:
        # State-less sink: a recovery needs no page and there is no instance to auto-resolve, so this is
        # a no-op (the connection_event lifecycle row is recorded by the runner, not here). ADR 0044 #56.
        return

    def backup_failed(self, name: str, *, kind: str, detail: str | None = None) -> None:
        log.warning("ALERT backup_failed: %r %s backup failed: %s", name, kind, detail or "")

    def store_privilege_warning(
        self, name: str, *, finding: str, excess_count: int, detail: str
    ) -> None:
        # An unobservable read never read the grant, so a "0 beyond the grant" count would read clean.
        counted = (
            f"{excess_count} privilege(s) beyond the documented grant"
            if finding == "over_granted"
            else "the principal's privileges were not read"
        )
        log.warning("ALERT store_privilege_warning: %r %s (%s): %s", name, finding, counted, detail)

    def store_privilege_clean(self, name: str) -> None:
        # The inverse (auto-resolve) event; no page, so DEBUG: the preflight already logged at INFO.
        log.debug("ALERT store_privilege_clean: %r store principal observed clean", name)

    def config_changed(
        self,
        name: str,
        *,
        fingerprint: str,
        previous_fingerprint: str,
        node: str | None,
        shard: str | None,
        baseline_action: str,
        baseline_actor: str | None,
        baseline_at: str,
        baseline_node: str | None,
    ) -> None:
        log.warning(
            "ALERT config_changed: %r %s (this node %s, engine shard %s; baseline actor %s; "
            "fingerprint %s, previous %s)",
            name,
            config_changed_detail(
                fingerprint=fingerprint,
                previous_fingerprint=previous_fingerprint,
                baseline_action=baseline_action,
                baseline_node=baseline_node,
                baseline_at=baseline_at,
            ),
            node,
            shard,
            baseline_actor,
            fingerprint,
            previous_fingerprint,
        )

    def leadership_acquired(self, node: str, *, role: str, epoch: int | None = None) -> None:
        log.warning(
            "ALERT leadership_acquired: node %r became %s (epoch=%s) — HA leadership moved",
            node,
            role,
            epoch,
        )

    def leadership_lost(self, node: str, *, role: str, reason: str) -> None:
        # The inverse (auto-resolve) event; informative but not a page — logged at INFO.
        log.info("ALERT leadership_lost: node %r is now %s (%s)", node, role, reason)

    def dr_activated(self, node: str, *, role: str) -> None:
        log.warning(
            "ALERT dr_activated: DR box %r PROMOTED (%s) — serving priority feeds (primary down)",
            node,
            role,
        )

    def dr_released(self, node: str, *, role: str) -> None:
        # The inverse (auto-resolve) event; a clean fail-back — logged at INFO, no page.
        log.info("ALERT dr_released: DR box %r released, handed back to %s", node, role)


#: The ``integrity_drift`` subject for a store-cipher refusal (BACKLOG #1169). Its own subject so it
#: throttles and routes apart from engine attestation and the audit-chain check.
STORE_CIPHER_SUBJECT = "store-cipher"

#: The cell-AAD table name the uploaded-file store seals under (``uploads.py``). Spelled here so this
#: module does not import the uploads store for one string; a test pins the two spellings together.
UPLOADED_FILE_TABLE = "uploaded_file"

#: The ``integrity_drift`` subject for a refused plaintext UPLOAD (BACKLOG #1169). Apart from
#: ``store-cipher`` on purpose. Legacy plaintext uploads are expected after a first key-enable and
#: refuse on every listing, so on the store's subject they would share its throttle, escalation and
#: suspend key. A real planted store row could then be throttled behind them, or muted along with
#: them.
UPLOAD_CIPHER_SUBJECT = "upload-cipher"


def alert_store_cipher_refusal(sink: AlertSink, table: str, column: str) -> None:
    """Raise the refusal alert for an unmarked value in ``table.column``: ``upload-cipher`` for the
    uploaded-file store, ``store-cipher`` for everything else.

    Names only the cell, which the cipher took from the AAD: never the row key and never the value,
    so it carries no PHI. Never raises: an alert failure must not change what a read or an open does."""
    if table == UPLOADED_FILE_TABLE:
        # The uploaded-file store (BACKLOG #1169, owner ruling 2026-09-23). Unlike a store column, a
        # plaintext file here is usually legitimate: one written before the key was enabled. So the
        # reason says what fixes it. Still the surface only: never a file id and never a filename.
        subject = UPLOAD_CIPHER_SUBJECT
        reason = (
            f"the keyed store refused a plaintext uploaded file ({table}.{column}): one stored before "
            "the key was enabled, or a planted one; it stays refused until 'messagefoundry "
            "rotate-key' seals it"
        )
    else:
        subject = STORE_CIPHER_SUBJECT
        reason = (
            f"the keyed store found an unmarked value in cipher column {table}.{column} (a stripped "
            "marker or a planted plaintext row); every read of it is refused"
        )
    try:
        sink.integrity_drift(subject, reason=reason, drift_count=1)
    except Exception:  # noqa: BLE001 — an alert-sink failure must never break a read path
        log.warning("store-cipher integrity alert could not be delivered")


def store_cipher_refusal_forwarder(
    sink: AlertSink, loop: asyncio.AbstractEventLoop
) -> Callable[[str, str], None]:
    """A cipher refusal hook that raises :func:`alert_store_cipher_refusal` on ``sink``.

    On the loop's own thread it alerts at once, so a refusal that aborts a store open is delivered
    before the caller unwinds. From any other thread (an off-loop decrypt) it hops onto ``loop``."""

    def _refused(table: str, column: str) -> None:
        try:
            running: asyncio.AbstractEventLoop | None = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is loop:
            alert_store_cipher_refusal(sink, table, column)
        else:
            loop.call_soon_threadsafe(alert_store_cipher_refusal, sink, table, column)

    return _refused
