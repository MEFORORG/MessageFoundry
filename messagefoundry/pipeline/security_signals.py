# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The security-signal rule layer: fixed detectors over the audit stream (vault BACKLOG #2613).

Before this, several security signals reached the audit log and nothing else, so a site with no
SIEM learned of them only by reading ``GET /audit``. Each detector here watches named audit actions
and raises one alert event type through
:meth:`~messagefoundry.pipeline.alerts.AlertSink.security_signal`.

**Where it reads, and why.** It is an observer on
:func:`~messagefoundry.store.audit_tee.emit_audit_tee`, which at least ``record_audit`` and the
in-transaction audit appends of every backend call after their commit. So it adds no commit and no
read to the request path, which already pays one commit per audited request. Reading the audit
table on a timer was the other choice; it would cost a query per tick and see a burst only after
the tick. The cost of the tap is one set lookup per row for an action no detector watches. It sees
only this process's rows, like the tee, and a row the tee misses (a cancellation landing between a
commit and its tee) is missed here too.

**What a detector never sends.** No message body, no message id, no audit row ``detail`` and no
typed username. The sign-in detector keys on the client address for that last reason: a typed
username can be a password typed into the wrong box. It counts ``auth.login_failed`` and no other
sign-in row. A refused local credential sign-in writes that row the same way in every lock state
(``auth/audit_visibility.py``), so the count does not say whether a local account is locked. A
directory (Kerberos or OIDC) lock refusal writes ``auth.directory_login_locked`` instead (BACKLOG
#3726), so it is not counted. Refusals that write some other action are not counted either. The
lock rows themselves are not read, and so an account lock raises no alert: that would show lock
state to a reader the 2026-09-28 owner ruling withholds it from.

**Refused peers are the one input that is not an audit row.** A listener refusing a peer at its
source allowlist or a connection cap writes a ``connection_event`` row only while the operator's
capture is on, and no audit row, so :func:`~messagefoundry.transports.admission.notify_refusal`
tells this layer directly. It passes the inbound's name and never the peer's address.

**Switched off, the layer still reports its own posture.** ``[alerts].security_signals = false`` is
a loosening :func:`~messagefoundry.config.settings.security_loosenings` names, so the posture
detector keeps running to raise it: every other detector stops.

**Bounded where the caller chooses the key.** A windowed detector tracks at most
:data:`MAX_SUBJECTS` subjects. Past :data:`MAX_SUBJECT_ALERTS` alerts in one window it raises under
one shared ``<prefix>:*`` subject instead, so a spread of addresses cannot open an alert instance,
and send a page, per address.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Final

from messagefoundry.config.settings import AlertsSettings
from messagefoundry.pipeline.alerts import AlertSink
from messagefoundry.pipeline.intake_bound import process_alert_subject, shorten_with_checksum
from messagefoundry.store.audit_tee import add_audit_observer, remove_audit_observer
from messagefoundry.transports.admission import add_refusal_observer, remove_refusal_observer

__all__ = [
    "MAX_SUBJECTS",
    "MAX_SUBJECT_ALERTS",
    "SECURITY_SIGNAL_TYPES",
    "SecuritySignalDetector",
    "SecuritySignalThresholds",
    "install_security_signals",
]

log = logging.getLogger(__name__)

SIGNIN_FAILURE_BURST: Final = "signin_failure_burst"
ACCESS_DENIED_BURST: Final = "access_denied_burst"
BODY_VIEW_BURST: Final = "body_view_burst"
BULK_EXPORT: Final = "bulk_export"
LOG_LEVEL_DEBUG: Final = "log_level_debug"
POSTURE_LOOSENED: Final = "posture_loosened"
PEER_REFUSED_BURST: Final = "peer_refused_burst"

#: Every event type this layer raises. ``config/settings.py`` ``_ALERT_EVENT_TYPES`` lists the same
#: seven by hand, because ``config/`` may not import ``pipeline/``; a test pins that each is there.
#: The ``posture_restored`` inverse is not one: it pages nobody, so no rule can route it.
SECURITY_SIGNAL_TYPES: Final[frozenset[str]] = frozenset(
    {
        SIGNIN_FAILURE_BURST,
        ACCESS_DENIED_BURST,
        BODY_VIEW_BURST,
        BULK_EXPORT,
        LOG_LEVEL_DEBUG,
        POSTURE_LOOSENED,
        PEER_REFUSED_BURST,
    }
)

#: The most subjects one windowed detector tracks. Past it the least recent subject is dropped.
MAX_SUBJECTS: Final = 4096
#: The most alerts one windowed detector raises under their own subjects in one window.
MAX_SUBJECT_ALERTS: Final = 5
#: Characters of a subject. SQL Server holds ``alert_instance.connection`` in 256.
_SUBJECT_LIMIT: Final = 200
_SWITCH_LIST_LIMIT: Final = 200

_DENIAL_ACTIONS: Final = frozenset(
    {"auth.permission_denied", "auth.channel_denied", "auth.mfa_denied"}
)
#: The pre-BACKLOG #3726 detail of a directory lock refusal under ``auth.login_failed``. Such a
#: refusal now has its own action, which no detector reads, and no writer stores this text. RETAINED
#: DELIBERATELY: removing a filter was out of #3726's scope, so this zero-weight stays until the
#: dead-directory-lock-filter removal, unallocated follow-up work, decides. Spelled here rather than
#: imported from
#: ``auth/``; a test pins it to ``DIRECTORY_LOCKED_REFUSAL_DETAIL``.
_DIRECTORY_LOCKED_DETAIL: Final = json.dumps({"provider": "ad", "reason": "locked"}, sort_keys=True)


@dataclass(frozen=True, slots=True)
class SecuritySignalThresholds:
    """The ``[alerts]`` security-signal settings. A count of 0 switches that detector off, and
    ``enabled`` False switches off every detector but the posture one.
    ``AlertsSettings`` owns the defaults; build one with :meth:`from_settings`."""

    window_seconds: float
    signin_failures: int
    denials: int
    body_views: int
    export_messages: int
    peer_refusals: int
    enabled: bool = True

    @classmethod
    def from_settings(cls, alerts: AlertsSettings) -> SecuritySignalThresholds:
        return cls(
            window_seconds=alerts.security_window_seconds,
            signin_failures=alerts.security_signin_failures,
            denials=alerts.security_denials,
            body_views=alerts.security_body_views,
            export_messages=alerts.security_export_messages,
            peer_refusals=alerts.security_peer_refusals,
            enabled=alerts.security_signals,
        )


def _bounded(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


class _Window:
    """One windowed detector: a sliding sum per subject over ``window_seconds``.

    :meth:`hit` adds a weight (1 for a row, the selected count for an export) and returns the sum
    when it reaches the threshold, then starts that subject again. Weights are at least 1, so a
    subject holds fewer than ``threshold`` entries, and each keeps a running total."""

    def __init__(self, threshold: int, window_seconds: float) -> None:
        self.threshold = threshold
        self.window_seconds = window_seconds
        self._seen: OrderedDict[str, tuple[deque[tuple[float, int]], list[int]]] = OrderedDict()
        #: Subjects that raised under their own name in the current window, and when.
        self._named: OrderedDict[str, float] = OrderedDict()

    def hit(self, subject: str, now: float, weight: int = 1) -> int | None:
        if self.threshold <= 0 or weight <= 0:
            return None
        held = self._seen.get(subject)
        if held is None:
            if len(self._seen) >= MAX_SUBJECTS:
                self._seen.popitem(last=False)
            held = self._seen[subject] = (deque(), [0])
        else:
            self._seen.move_to_end(subject)
        entries, total = held
        cutoff = now - self.window_seconds
        while entries and entries[0][0] <= cutoff:
            total[0] -= entries.popleft()[1]
        entries.append((now, weight))
        total[0] += weight
        if total[0] < self.threshold:
            return None
        del self._seen[subject]
        return total[0]

    def named(self, subject: str, now: float) -> bool:
        """Whether ``subject`` may raise under its own name: it already did this window, or fewer
        than :data:`MAX_SUBJECT_ALERTS` distinct subjects have. Records it when it may."""
        cutoff = now - self.window_seconds
        while self._named and next(iter(self._named.values())) <= cutoff:
            self._named.popitem(last=False)
        if subject in self._named or len(self._named) < MAX_SUBJECT_ALERTS:
            self._named.pop(subject, None)
            self._named[subject] = now
            return True
        return False


@dataclass(frozen=True, slots=True)
class _Burst:
    """What one windowed detector raises, and how it names its subject."""

    signal: str
    prefix: str
    sentence: str  # formatted with {total} and {window}
    by_address: bool = False


_SIGNIN = _Burst(
    SIGNIN_FAILURE_BURST,
    "signin",
    "{total} refused sign-ins from this address within {window}",
    True,
)
_DENIED = _Burst(
    ACCESS_DENIED_BURST, "account", "{total} refused requests by this account within {window}"
)
_BODIES = _Burst(
    BODY_VIEW_BURST, "account", "{total} stored-body reads by this account within {window}"
)
_EXPORT = _Burst(
    BULK_EXPORT, "account", "{total} messages exported by this account within {window}"
)
#: Prefixed ``inbound``, so the subject is spelled as ``connection_names.inbound_record_name``
#: spells an inbound; a test pins the two together.
_REFUSED = _Burst(
    PEER_REFUSED_BURST,
    "inbound",
    "{total} connections refused by this inbound's source allowlist or connection caps "
    "within {window}; once raised, it is quiet for the rest of the window",
)


def _detail_of(detail: str | None) -> dict[str, Any]:
    """The row's detail as a JSON object, or empty when it is not one."""
    if not detail:
        return {}
    try:
        parsed = json.loads(detail)
    except ValueError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _count_field(detail: str | None, key: str) -> int:
    value = _detail_of(detail).get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _one(detail: str | None) -> int:
    return 1


def _signin_weight(detail: str | None) -> int:
    return 0 if detail == _DIRECTORY_LOCKED_DETAIL else 1


def _export_size(detail: str | None) -> int:
    return _count_field(detail, "selected")


def _outbound_weight(detail: str | None) -> int:
    return 1 if _count_field(detail, "count") > 0 else 0


def _response_weight(detail: str | None) -> int:
    # `body: false` returns the replies' metadata only, so it reads no body.
    return 1 if _detail_of(detail).get("body") is True and _count_field(detail, "count") > 0 else 0


#: The audited reads of a stored body this layer counts, each with what makes a row one. A read
#: that returned no body (no payload, or a reply read without its body) does not count.
_BODY_READS: Final[dict[str, Callable[[str | None], int]]] = {
    "message_body_view": _one,
    "attachment_download": _one,
    "outbound.read": _outbound_weight,
    "response.read": _response_weight,
}


class SecuritySignalDetector:
    """The fixed detectors. :meth:`observe` is an :data:`~messagefoundry.store.audit_tee.AuditObserver`.

    It runs inline on the audit writer's path, so it does only in-memory work and never raises.
    :meth:`observe_refusal` runs inline on a listener's accept path the same way.

    ``identity`` returns which engine process this is (``Engine.instance_identity``), or ``None``
    for a lone engine. It is read when a start's row arrives, and suffixes the posture subject, so
    a clean start resolves only its own process's ``posture_loosened``.
    """

    def __init__(
        self,
        sink: AlertSink,
        thresholds: SecuritySignalThresholds,
        *,
        clock: Callable[[], float] = time.monotonic,
        identity: Callable[[], str | None] = lambda: None,
    ) -> None:
        self._sink = sink
        t = thresholds
        self._window_label = f"{t.window_seconds:g} s"
        self._clock = clock
        self._identity = identity
        #: The posture_loosened subject this detector last raised and has not seen resolved.
        self._posture_raised: str | None = None
        #: Listeners whose refusal burst raised, mapped to when their quiet ends. A refused
        #: connection costs the peer nothing, so without it a flood would raise, and write an alert
        #: row, every ``peer_refusals`` refusals. Keyed by inbound name, so bounded by the graph,
        #: and trimmed past :data:`MAX_SUBJECTS` all the same.
        self._refusals_quiet: OrderedDict[str, float] = OrderedDict()
        windows = {
            _SIGNIN: _Window(t.signin_failures, t.window_seconds),
            _DENIED: _Window(t.denials, t.window_seconds),
            _BODIES: _Window(t.body_views, t.window_seconds),
            _EXPORT: _Window(t.export_messages, t.window_seconds),
        }
        self._bursts: dict[str, tuple[_Burst, _Window, Callable[[str | None], int]]] = {
            "auth.login_failed": (_SIGNIN, windows[_SIGNIN], _signin_weight),
            **dict.fromkeys(_DENIAL_ACTIONS, (_DENIED, windows[_DENIED], _one)),
            **{a: (_BODIES, windows[_BODIES], w) for a, w in _BODY_READS.items()},
            "messages_export": (_EXPORT, windows[_EXPORT], _export_size),
        }
        self._signin = windows[_SIGNIN]  # read by a test of the subject bound
        # The layer switched off is decided here, once per input: the audit actions narrow to the
        # posture row, and the refusal window gets a zero threshold, which counts nothing.
        self._refused = _Window(t.peer_refusals if t.enabled else 0, t.window_seconds)
        #: Whether :meth:`observe_refusal` can ever raise, so the installer can skip the observer.
        self.counts_refusals = self._refused.threshold > 0
        #: The audit actions some running detector reads; :meth:`observe` ignores every other.
        self.actions: frozenset[str] = (
            frozenset(
                {
                    *self._bursts,
                    "logging_level_change",
                    "logging_level_change_denied",
                    "config_loaded",
                }
            )
            if t.enabled
            else frozenset({"config_loaded"})
        )

    def observe(
        self,
        action: str,
        actor: str | None,
        channel_id: str | None,
        client: str | None,
        detail: str | None,
    ) -> None:
        if action not in self.actions:
            return
        try:
            burst = self._bursts.get(action)
            if burst is not None:
                kind, window, weight_of = burst
                key = client if kind.by_address else actor
                self._on_burst(kind, window, key, weight_of(detail))
            elif action == "logging_level_change":
                self._on_level(actor, detail, "to", "the live log level was raised to DEBUG by")
            elif action == "logging_level_change_denied":
                self._on_level(
                    actor,
                    detail,
                    "requested",
                    "a production instance refused a DEBUG log level, asked for by",
                )
            elif action == "config_loaded":
                self._on_config_loaded(detail)
        except Exception as exc:  # noqa: BLE001 - a detector fault must not reach the audit writer
            log.warning("security-signal detector failed: %s", type(exc).__name__)

    def observe_refusal(self, connection: str) -> None:
        """A :data:`~messagefoundry.transports.admission.RefusalObserver`: the inbound
        ``connection`` refused a peer at its source allowlist or a connection cap."""
        try:
            now = self._clock()
            quiet = self._refusals_quiet
            if quiet.get(connection, now) > now:
                return  # raised this window: not even counted, which is the cheap path
            quiet.pop(connection, None)
            if self._on_burst(_REFUSED, self._refused, connection, 1):
                quiet[connection] = now + self._refused.window_seconds
                if len(quiet) > MAX_SUBJECTS:
                    quiet.popitem(last=False)
        except Exception as exc:  # noqa: BLE001 - a detector fault must not reach the listener
            log.warning("security-signal detector failed: %s", type(exc).__name__)

    def _on_burst(self, burst: _Burst, window: _Window, key: str | None, weight: int) -> bool:
        """Count ``weight`` for ``key``; True when that raised the alert."""
        key = key or "unknown"
        now = self._clock()
        total = window.hit(key, now, weight)
        if total is None:
            return False
        # A checksum keeps two long keys with one head apart, where a plain cut would merge them.
        subject = shorten_with_checksum(f"{burst.prefix}:{key}", _SUBJECT_LIMIT)
        sentence = burst.sentence.format(total=total, window=self._window_label)
        if not window.named(subject, now):
            subject = f"{burst.prefix}:*"
            sentence += f"; {MAX_SUBJECT_ALERTS} other subjects already raised this window"
        self._raise(burst.signal, subject, total, sentence)
        return True

    def _on_level(self, actor: str | None, detail: str | None, key: str, sentence: str) -> None:
        if str(_detail_of(detail).get(key, "")).upper() == "DEBUG":
            self._raise(LOG_LEVEL_DEBUG, "logging:debug", 1, f"{sentence} {actor or 'unknown'}")

    def _on_config_loaded(self, detail: str | None) -> None:
        switches = _detail_of(detail).get("loosenings")
        # None means the start could not read its list; that is no finding either way.
        if not isinstance(switches, list):
            return
        try:
            identity = self._identity()
        except Exception as exc:  # noqa: BLE001 - fail toward raising: the bare subject still pages
            log.warning("the engine identity could not be read: %s", type(exc).__name__)
            identity = None
        subject = process_alert_subject("posture:start", identity)
        if not switches:
            self._restore(subject)
            return
        names = _bounded(", ".join(str(s) for s in switches), _SWITCH_LIST_LIMIT)
        self._posture_raised = subject
        self._raise(
            POSTURE_LOOSENED,
            subject,
            len(switches),
            f"the engine started with {len(switches)} security loosening(s): {names}",
        )

    def release(self) -> None:
        """Resolve the ``posture_loosened`` this detector raised, as its process stops. For a
        process whose identity changes on every start, an unpinned cluster node: its next start
        reports under a new subject, so nothing could resolve the old one later."""
        if self._posture_raised is not None:
            self._restore(self._posture_raised)

    def _restore(self, subject: str) -> None:
        self._posture_raised = None
        self._notify("posture_restored", lambda: self._sink.posture_restored(subject))

    def _raise(self, signal: str, subject: str, count: int, detail: str) -> None:
        self._notify(
            signal,
            lambda: self._sink.security_signal(subject, signal=signal, count=count, detail=detail),
        )

    @staticmethod
    def _notify(event: str, call: Callable[[], None]) -> None:
        try:
            call()
        except Exception as exc:  # noqa: BLE001 - an alert-sink failure must not reach the writer
            log.warning(
                "security-signal alert %s could not be raised: %s", event, type(exc).__name__
            )


def install_security_signals(
    sink: AlertSink,
    thresholds: SecuritySignalThresholds,
    loop: asyncio.AbstractEventLoop,
    *,
    identity: Callable[[], str | None] = lambda: None,
    resolve_on_stop: bool = False,
) -> Callable[[], None]:
    """Register a :class:`SecuritySignalDetector` on the audit tee, and on the listeners' refusal
    observers while it counts refusals; returns the function that removes it.

    ``resolve_on_stop`` is for a process whose ``identity`` changes on every start, an unpinned
    cluster node: removing the detector then resolves the ``posture_loosened`` it raised, as
    :class:`~messagefoundry.pipeline.intake_bound.IntakeBoundMonitor` clears its own alerts. The
    removal must run on ``loop``'s thread, before the store closes.

    A row or refusal on ``loop``'s own thread is judged at once. One on another thread is hopped
    onto ``loop``, so the detector's state and the sink are only touched from one thread."""
    detector = SecuritySignalDetector(sink, thresholds, identity=identity)

    def _on_loop(judge: Callable[..., None], *args: str | None) -> None:
        try:
            running: asyncio.AbstractEventLoop | None = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is loop:
            judge(*args)
        elif not loop.is_closed():
            loop.call_soon_threadsafe(judge, *args)

    def _observe(
        action: str,
        actor: str | None,
        channel_id: str | None,
        client: str | None,
        detail: str | None,
    ) -> None:
        if action not in detector.actions:
            return  # the common case: one set lookup per row, and no thread hop
        _on_loop(detector.observe, action, actor, channel_id, client, detail)

    def _refused(connection: str) -> None:
        _on_loop(detector.observe_refusal, connection)

    add_audit_observer(_observe)
    if detector.counts_refusals:
        add_refusal_observer(_refused)

    def _remove() -> None:
        remove_audit_observer(_observe)
        remove_refusal_observer(_refused)
        if resolve_on_stop:
            detector.release()

    return _remove
