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
username can be a password typed into the wrong box. It counts ``auth.login_failed``, which the
engine writes once per refused sign-in in every lock state (``auth/audit_visibility.py``), so the
count does not say whether an account is locked. The lock rows themselves are not read, and so an
account lock raises no alert: that would show lock state to a reader the 2026-09-28 owner ruling
withholds it from.

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
from messagefoundry.store.audit_tee import add_audit_observer, remove_audit_observer

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

#: Every event type this layer raises. ``config/settings.py`` ``_ALERT_EVENT_TYPES`` lists the same
#: six by hand, because ``config/`` may not import ``pipeline/``; a test pins that each is there.
SECURITY_SIGNAL_TYPES: Final[frozenset[str]] = frozenset(
    {
        SIGNIN_FAILURE_BURST,
        ACCESS_DENIED_BURST,
        BODY_VIEW_BURST,
        BULK_EXPORT,
        LOG_LEVEL_DEBUG,
        POSTURE_LOOSENED,
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
#: The detail of a directory sign-in refused by a live lock. That row is withheld from readers
#: without ``users:manage`` and has no visible stand-in, so counting it could show a lock. Spelled
#: here rather than imported from ``auth/``; a test pins it to ``DIRECTORY_LOCKED_REFUSAL_DETAIL``.
_DIRECTORY_LOCKED_DETAIL: Final = json.dumps({"provider": "ad", "reason": "locked"}, sort_keys=True)


@dataclass(frozen=True, slots=True)
class SecuritySignalThresholds:
    """The ``[alerts]`` security-signal settings. A count of 0 switches that detector off.
    ``AlertsSettings`` owns the defaults; build one with :meth:`from_settings`."""

    window_seconds: float
    signin_failures: int
    denials: int
    body_views: int
    export_messages: int

    @classmethod
    def from_settings(cls, alerts: AlertsSettings) -> SecuritySignalThresholds:
        return cls(
            window_seconds=alerts.security_window_seconds,
            signin_failures=alerts.security_signin_failures,
            denials=alerts.security_denials,
            body_views=alerts.security_body_views,
            export_messages=alerts.security_export_messages,
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
    """

    def __init__(
        self,
        sink: AlertSink,
        thresholds: SecuritySignalThresholds,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._sink = sink
        t = thresholds
        self._window_label = f"{t.window_seconds:g} s"
        self._clock = clock
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
        #: The audit actions some detector reads.
        self.actions: frozenset[str] = frozenset(
            {*self._bursts, "logging_level_change", "logging_level_change_denied", "config_loaded"}
        )

    def observe(
        self,
        action: str,
        actor: str | None,
        channel_id: str | None,
        client: str | None,
        detail: str | None,
    ) -> None:
        try:
            burst = self._bursts.get(action)
            if burst is not None:
                self._on_burst(*burst, actor=actor, client=client, detail=detail)
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

    def _on_burst(
        self,
        burst: _Burst,
        window: _Window,
        weight_of: Callable[[str | None], int],
        *,
        actor: str | None,
        client: str | None,
        detail: str | None,
    ) -> None:
        key = (client if burst.by_address else actor) or "unknown"
        now = self._clock()
        total = window.hit(key, now, weight_of(detail))
        if total is None:
            return
        subject = _bounded(f"{burst.prefix}:{key}", _SUBJECT_LIMIT)
        sentence = burst.sentence.format(total=total, window=self._window_label)
        if not window.named(subject, now):
            subject = f"{burst.prefix}:*"
            sentence += f"; {MAX_SUBJECT_ALERTS} other subjects already raised this window"
        self._raise(burst.signal, subject, total, sentence)

    def _on_level(self, actor: str | None, detail: str | None, key: str, sentence: str) -> None:
        if str(_detail_of(detail).get(key, "")).upper() == "DEBUG":
            self._raise(LOG_LEVEL_DEBUG, "logging:debug", 1, f"{sentence} {actor or 'unknown'}")

    def _on_config_loaded(self, detail: str | None) -> None:
        switches = _detail_of(detail).get("loosenings")
        # None means the start could not read its list; that is no finding either way.
        if not isinstance(switches, list) or not switches:
            return
        names = _bounded(", ".join(str(s) for s in switches), _SWITCH_LIST_LIMIT)
        self._raise(
            POSTURE_LOOSENED,
            "posture:start",
            len(switches),
            f"the engine started with {len(switches)} security loosening(s): {names}",
        )

    def _raise(self, signal: str, subject: str, count: int, detail: str) -> None:
        try:
            self._sink.security_signal(subject, signal=signal, count=count, detail=detail)
        except Exception as exc:  # noqa: BLE001 - an alert-sink failure must not reach the writer
            log.warning(
                "security-signal alert %s could not be raised: %s", signal, type(exc).__name__
            )


def install_security_signals(
    sink: AlertSink,
    thresholds: SecuritySignalThresholds,
    loop: asyncio.AbstractEventLoop,
) -> Callable[[], None]:
    """Register a :class:`SecuritySignalDetector` on the audit tee; returns the function that
    removes it.

    A row committed on ``loop``'s own thread is judged at once. One committed on another thread is
    hopped onto ``loop``, so the detector's state and the sink are only touched from one thread."""
    detector = SecuritySignalDetector(sink, thresholds)

    def _observe(
        action: str,
        actor: str | None,
        channel_id: str | None,
        client: str | None,
        detail: str | None,
    ) -> None:
        if action not in detector.actions:
            return  # the common case: one set lookup per row, and no thread hop
        try:
            running: asyncio.AbstractEventLoop | None = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is loop:
            detector.observe(action, actor, channel_id, client, detail)
        elif not loop.is_closed():
            loop.call_soon_threadsafe(detector.observe, action, actor, channel_id, client, detail)

    add_audit_observer(_observe)
    return lambda: remove_audit_observer(_observe)
