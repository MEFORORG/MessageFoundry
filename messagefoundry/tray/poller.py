# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Background status poller for the tray (ADR 0113 §3).

A single daemon thread ticks every few seconds: read the local SCM state, probe the tokenless
``/health`` and ``/ui``, derive the :class:`~messagefoundry.tray.state.TrayState`, and hand a :class:`PollResult`
to the shell's update callback (which repaints the icon on the UI thread). The cadence tightens
to ``waitHint/10`` while a service transition is in flight. A tick that *raises* is logged and
published as ``UNKNOWN`` rather than ending the thread: an icon frozen on its last good reading
reports stale state as live, and says nothing about having stopped. That stand-in is a **display**
fallback only -- it is kept out of every piece of cross-tick memory, for the reasons set out on
:meth:`StatusPoller._unknown_result`.

The guarded region is the whole of the tick that reads the world: the monotonic clock read that
opens it and the three injected probes behind :meth:`StatusPoller.poll_once`. What runs *after
that guard closes* is the cadence computation and the wait, pure over the tick's own result, so
no injected dependency is left outside it. Both of the loop's guards -- the tick and the update
callback -- log through a :class:`_FailureRun`, which states there why a per-pass traceback
cannot be left unthrottled on a loop this one's cadence.

The timing that turns raw readings into :class:`~messagefoundry.tray.state.ProbeInputs` — the boot-grace clock and
stuck-pending detection — is the **pure** :func:`advance`, keyed to a **monotonic** ``now`` so a
laptop sleep/resume cannot mis-age a window. Toast emission is transition-only and rate-limited.
All the stateful logic is dependency-injected (SCM reader, probes, clock) so it is unit-testable
without a real service or network.
"""

from __future__ import annotations

import functools
import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

import httpx

from messagefoundry.tray.config import TrayConfig, is_tls_url
from messagefoundry.tray.probe import (
    LoadedPin,
    load_pin,
    make_probe_client,
    probe_health,
    probe_ui,
    read_pin,
)
from messagefoundry.tray.state import (
    HealthProbe,
    ProbeInputs,
    ScmState,
    StatusSnapshot,
    Toast,
    TrayState,
    UiProbe,
    derive_state,
    next_poll_seconds,
    transition_toast,
)
from messagefoundry.tray.winsvc import ScmReading, query_scm_state

log = logging.getLogger("messagefoundry.tray.poller")

TOAST_MIN_INTERVAL_S = 30.0
_STOP_JOIN_TIMEOUT_S = 3.0


def _is_emission(n: int) -> bool:
    """True on the 1st, 2nd, 4th, 8th ... of something -- that is, when ``n`` is a power of two."""
    return n & (n - 1) == 0


@dataclass(frozen=True)
class _FailureRun:
    """A run of consecutive failures of one thing, logged with a backoff. Immutable.

    Emissions go on the 1st, 2nd, 4th, 8th ... failure *of a cause*. Geometric, because the loop
    retries on a fixed cadence and an unthrottled traceback per pass is what collapses a
    rotating log: at :data:`~messagefoundry.tray.state.POLL_BASE_S` a thing that stays broken
    writes on the order of seventeen thousand tracebacks a day into the 1 MB x 3 ``tray.log``
    that ``tray.__main__._setup_logging`` opens, rotating the whole window out within hours --
    and the first record to go is the one naming the original cause. Backed off it is about
    fifteen a day, and the original cause survives.

    The consecutive count rides in every message, which is what makes the suppression legible:
    a record reading ``consecutive failures: 512`` says on its face that 511 went unwritten, so
    a reader is never misled into treating the log as a complete list of attempts.

    A *changed* cause is never held back, because it is the only record in a long run carrying
    anything the reader does not already have. **That bounds what the backoff can promise**: the
    cause is keyed on the exception's type and message, so one whose message varies every pass
    (an embedded handle, address or errno detail) reads as a new cause each time and is not
    throttled at all. That is the deliberate trade -- the alternative, a bound that holds under
    a churning message, can only be had by suppressing a changed cause, and a backoff that hides
    a new fault behind an old one is worth less than no backoff.

    A value object for the same reason :class:`Tracking` is one: three pieces of cross-call
    memory only ever meaningful together, so one rebind is the whole state change and one
    default is the whole reset.
    """

    count: int = 0  # consecutive failures, whatever the cause; 0 whenever the thing is healthy
    signature: tuple[str, str] | None = None  # exception type and message of the current cause
    cause_run: int = 0  # failures since the cause last changed -- what the schedule counts

    def record(self, exc: Exception, message: str) -> _FailureRun:
        """The run after one more failure, having logged it unless the backoff holds it back."""
        signature = (type(exc).__name__, str(exc))
        # A changed cause starts its own schedule rather than inheriting where the previous one
        # had got to. Carrying the old position forward would log a new fault once and then go
        # silent for as many passes again -- deep in a long run, hundreds -- which is the
        # opposite of never holding a new cause back.
        cause_run = self.cause_run + 1 if signature == self.signature else 1
        if _is_emission(cause_run):
            # The count is the WHOLE run, not this cause's share: an operator reading the record
            # needs to know how long the thing has been failing, not just since it changed how.
            log.error("%s (consecutive failures: %d)", message, self.count + 1, exc_info=exc)
        return _FailureRun(self.count + 1, signature, cause_run)

    def clear(self, what: str) -> _FailureRun:
        """The healthy run, noting how long the old one lasted if there was one to close.

        That line is what keeps the backoff honest. Without it an absence of recent tracebacks
        has two readings -- recovered, or still failing and merely gone quiet -- and nothing in
        the log tells them apart. One line per run, so it cannot itself become the flood.
        """
        if self.count:
            log.info("tray %s recovered after %d consecutive failures", what, self.count)
        return _FailureRun()


@dataclass(frozen=True)
class Tracking:
    """Cross-tick memory the pure :func:`advance` carries forward (monotonic timestamps)."""

    running_since: float | None = None  # when SCM was first seen RUNNING this run
    pending_since: float | None = None  # last reported progress in the current pending state
    last_checkpoint: int | None = None
    last_scm: ScmState | None = None


@dataclass(frozen=True)
class PollResult:
    """One tick's output: the render snapshot, the derived inputs, the raw reading, a maybe-toast."""

    snapshot: StatusSnapshot
    inputs: ProbeInputs
    reading: ScmReading
    toast: Toast | None = None


_PENDING = (ScmState.START_PENDING, ScmState.STOP_PENDING)

# What a tick that *raised* stands in with: SCM unqueryable, both probes dark. Deliberately
# clock-free and tracking-free constants -- see :meth:`StatusPoller._unknown_result` for why the
# synthetic reading must never reach `advance`.
_UNKNOWN_READING = ScmReading(state=ScmState.UNAVAILABLE)
_UNKNOWN_INPUTS = ProbeInputs(scm=ScmState.UNAVAILABLE, health=HealthProbe.DOWN, ui=UiProbe.UNKNOWN)
_UNKNOWN_STATE = derive_state(_UNKNOWN_INPUTS)  # UNKNOWN, derived through the reducer not asserted


def advance(
    tracking: Tracking,
    reading: ScmReading,
    health: HealthProbe,
    ui: UiProbe,
    now: float,
) -> tuple[Tracking, ProbeInputs]:
    """Fold a new reading into the tracking state and produce the reducer inputs. Pure.

    ``now`` must be a monotonic clock value. Grace windows are elapsed = ``now - since``; the boot
    grace is keyed to when SCM *entered* RUNNING (not to a user action), so a normal boot or NSSM
    auto-restart does not flash WEDGED. The pending clock is keyed to the last *reported progress*,
    so a healthy slow start that keeps advancing its checkpoint never ages into WEDGED.
    """
    st = reading.state
    prev = tracking.last_scm

    running_since = (
        (tracking.running_since if prev is ScmState.RUNNING else now)
        if st is ScmState.RUNNING
        else None
    )

    same_pending = st in _PENDING and prev is st

    if same_pending and tracking.last_checkpoint is not None:
        checkpoint_advancing = reading.checkpoint > tracking.last_checkpoint
    else:
        checkpoint_advancing = True  # a freshly-entered pending state is assumed to be progressing

    # ``dwWaitHint`` is the service's estimate for the NEXT checkpoint, not for the whole
    # transition (Microsoft's DoStartSvc contract), so the pending clock re-anchors each time the
    # checkpoint increases. Increase-only (``>`` above, never ``>=``): a service that reports the
    # same checkpoint forever keeps its first anchor and still ages past the hint into WEDGED.
    # ``checkpoint_advancing`` is the whole condition -- it is False only on a same-pending tick.
    # STOP_PENDING re-anchors too, harmlessly: derive_state maps it to STOPPING either way.
    pending_since = (
        (now if checkpoint_advancing else tracking.pending_since) if st in _PENDING else None
    )

    inputs = ProbeInputs(
        scm=st,
        health=health,
        ui=ui,
        running_elapsed_s=(now - running_since) if running_since is not None else None,
        checkpoint_advancing=checkpoint_advancing,
        pending_elapsed_s=(now - pending_since) if pending_since is not None else None,
        wait_hint_s=reading.wait_hint_s,
    )
    new_tracking = Tracking(
        running_since=running_since,
        pending_since=pending_since,
        last_checkpoint=reading.checkpoint,
        last_scm=st,
    )
    return new_tracking, inputs


class StatusPoller:
    """Owns the poll thread and the httpx probe client. Thread-safe start/stop."""

    def __init__(
        self,
        config: TrayConfig,
        on_update: Callable[[PollResult], None],
        *,
        scm_reader: Callable[[str], ScmReading] = query_scm_state,
        health_probe: Callable[[httpx.Client], HealthProbe] = probe_health,
        ui_probe: Callable[[httpx.Client], UiProbe] = probe_ui,
        client_factory: Callable[[str], httpx.Client] | None = None,
        clock: Callable[[], float] = time.monotonic,
        toast_min_interval_s: float = TOAST_MIN_INTERVAL_S,
    ) -> None:
        self._config = config
        self._on_update = on_update
        self._scm_reader = scm_reader
        self._health_probe = health_probe
        self._ui_probe = ui_probe
        # The default factory carries the config's certificate pin, so a caller that injects its
        # own factory owns the trust decision too.
        #: The pin the default client trusts and follows. See :meth:`_follow_the_pin`. Only for
        #: https: httpx ignores ``verify`` for plain http, so a pin there has nothing to follow.
        self._pin: str | None = None
        if client_factory is None:
            if is_tls_url(config.engine_url):
                self._pin = config.engine_cacert
            client_factory = functools.partial(make_probe_client, cacert=config.engine_cacert)
        self._client_factory = client_factory
        #: The pin bytes the current client was built from, or None when it was not built from them.
        self._pin_pem: bytes | None = None
        #: The last changed pin bytes that would not load, so the same bytes are logged only once.
        self._pin_refused: bytes | None = None
        self._clock = clock
        self._toast_min_interval_s = toast_min_interval_s
        self._client: httpx.Client | None = None
        self._tracking = Tracking()
        self._last_state: TrayState | None = None
        self._last_toast_at: float | None = None
        self._poll_failures = _FailureRun()
        self._callback_failures = _FailureRun()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._open_client()
        self._thread = threading.Thread(target=self._run, name="mefor-tray-poller", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=_STOP_JOIN_TIMEOUT_S)
        if self._client is not None:
            self._client.close()
            self._client = None

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                # The clock read opens the tick, so it sits inside the guard with the probes.
                # `clock` is an injected dependency of exactly their rank, and one that raises
                # from outside the guard ends the poll thread -- the one failure this boundary
                # exists to prevent, left reachable above the claim the module docstring makes.
                result = self.poll_once(self._clock())
            except Exception as exc:  # supervisory boundary -- see the module docstring
                if self._stop.is_set():
                    # `stop()` sets the event, joins for _STOP_JOIN_TIMEOUT_S, then closes the
                    # probe client; two probes at DEFAULT_TIMEOUT_S can outlast that join, and
                    # httpx then raises a bare RuntimeError through `probe_health`/`probe_ui`,
                    # which catch only httpx.HTTPError. That is the shutdown, not a fault, so it
                    # does not warrant an ERROR traceback on every clean exit. It is still
                    # recorded at INFO -- the level `_setup_logging` pins the root logger to, and
                    # the tray offers no way to lower it -- because this branch is reached by
                    # *any* exception raised inside the join window, so a genuine defect landing
                    # there must not vanish. One line and a repr, not a traceback: enough to say
                    # what happened without reading as a failure on a clean exit.
                    log.info("tray status poll raised while stopping: %r", exc)
                else:
                    self._poll_failures = self._poll_failures.record(
                        exc, "tray status poll raised; publishing UNKNOWN for this tick"
                    )
                result = self._unknown_result()
            else:
                self._poll_failures = self._poll_failures.clear("status poll")
            if self._stop.is_set():
                # Best-effort, not a guarantee: `stop()` can still land between this check and
                # the call below. It is worth having anyway, because it closes the wide case (a
                # tick already in flight when stop() was called), and the residual race is benign
                # -- `winshell._post` no-ops on a torn-down window handle.
                return
            try:
                self._on_update(result)
            except Exception as exc:  # a UI callback must never kill the loop (supervisory)
                if self._stop.is_set():
                    # The same shutdown window the poll guard above handles, reached the same
                    # way: `stop()` can land between that `is_set` check and this call, and the
                    # callback then repaints a torn-down shell. Claiming a fault for that would
                    # put an ERROR traceback in tray.log on every clean exit. INFO for the same
                    # reason it is INFO there -- any exception raised in the window lands here,
                    # so a genuine defect must not vanish.
                    log.info("tray status callback raised while stopping: %r", exc)
                else:
                    # Backed off for the reason the poll path is, and it has to be: a callback
                    # that raises once (torn-down window handle, iconset load failure) raises
                    # every tick, on the same cadence, into the same rotating log. Left
                    # unthrottled it would rotate out the very evidence the poll path's backoff
                    # exists to preserve, so that guarantee would hold only while this sibling
                    # happened to be quiet.
                    self._callback_failures = self._callback_failures.record(
                        exc, "tray status callback raised"
                    )
            else:
                self._callback_failures = self._callback_failures.clear("status callback")
            interval = next_poll_seconds(result.snapshot.state, result.inputs.wait_hint_s)
            self._stop.wait(interval)

    def poll_once(self, now: float) -> PollResult:
        """Read all probes once and produce a :class:`PollResult`. Does I/O via the injected deps."""
        self._follow_the_pin()
        reading = self._scm_reader(self._config.service_name)
        client = self._client
        health = self._health_probe(client) if client is not None else HealthProbe.DOWN
        ui = self._ui_probe(client) if client is not None else UiProbe.UNKNOWN
        self._tracking, inputs = advance(self._tracking, reading, health, ui, now)
        return self._build_result(inputs, reading, now)

    def _open_client(self) -> None:
        loaded = load_pin(self._pin) if self._pin is not None else None
        if loaded is None:
            # No pin configured, or not loadable yet: the factory decides, and a pin that loads
            # later is picked up by `_follow_the_pin` because nothing has been recorded.
            self._client = self._client_factory(self._config.engine_url)
            return
        self._adopt_pin(loaded)

    def _follow_the_pin(self) -> None:
        """Rebuild the client when the pinned certificate changes, without a tray restart.

        Two events change it. The engine mints its pair on its first run, so a tray started before
        then has no pin to load and reads the engine as down. And the engine renews its certificate
        early, at startup (BACKLOG #1276), so a tray pinned to the old one would fail verification
        against a running engine and show it DOWN until restarted. A context reads its file once,
        when it is built, so neither reaches a client already open.

        **The trigger is a read of the file on every tick, compared byte for byte with what the
        client was built from.** Waiting for a verification failure was the alternative, and it
        cannot be seen from here: the probes fold every transport error, a refused connection and a
        failed handshake alike, into ``DOWN``. The steady-state cost is one read of a small local
        file beside two HTTP round trips, and bytes are compared rather than hashed because the
        comparison is exact and needs no digest.

        **The pin is never dropped.** Only bytes that LOAD replace the client: a missing,
        unreadable, empty or half-written file keeps the current one, so a renewal caught mid-write
        costs nothing. The new client pins the new file alone. A certificate that is not the
        engine's therefore fails verification exactly as before, and nothing here reaches for the
        OS trust store or turns verification off. The record moves only after the new client
        exists, so a build that raises is retried on the next tick.

        Changed bytes that do not load are logged once, so a file that stays broken says so
        instead of the engine silently reading DOWN, and a renewal caught mid-write costs one line.
        The load itself is retried every tick even for bytes already logged. Skipping it would be
        wrong: the bytes read here and the bytes the load saw can differ, so bytes recorded as
        refused may be a good certificate the load simply never saw.
        """
        if self._pin is None or self._stop.is_set():
            return
        current = read_pin(self._pin)
        if current is None or current == self._pin_pem:
            return  # unreadable (keep the current client) or unchanged (nothing to do)
        loaded = load_pin(self._pin)
        if loaded is None:
            # Present but not loadable: empty, half-written, or rewritten mid-load.
            if current != self._pin_refused:
                self._pin_refused = current
                log.info(
                    "engine certificate %s changed but does not load; keeping the current client",
                    self._pin,
                )
            return
        log.info(
            "engine certificate %s %s; rebuilding the probe client",
            self._pin,
            "now loads" if self._pin_pem is None else "has changed",
        )
        old = self._client
        self._adopt_pin(loaded)
        if old is not None:
            old.close()

    def _adopt_pin(self, loaded: LoadedPin) -> None:
        """Open a client trusting exactly the loaded context, and record the bytes it came from."""
        pem, context = loaded
        self._client = make_probe_client(self._config.engine_url, cacert=self._pin, pinned=context)
        self._pin_pem = pem

    def _unknown_result(self) -> PollResult:
        """The stand-in :class:`PollResult` for a tick that raised.

        A **display** fallback, not a state transition. The synthetic reading is deliberately kept
        out of both pieces of cross-tick memory, because it is a statement about the *poller*
        having failed, not an observation of the service:

        * It never reaches :func:`advance`. An ``UNAVAILABLE`` fold clears ``running_since`` and
          ``pending_since``, so the next real RUNNING tick would re-anchor the boot grace at zero.
          :func:`~messagefoundry.tray.state.derive_state` needs ``running_elapsed_s`` past
          :data:`~messagefoundry.tray.state.BOOT_GRACE_S` to return ``WEDGED``, so a poll raising
          more often than that grace would pin a genuinely wedged engine at ``STARTING`` for as
          long as it kept failing -- defeating the one detection the tray exists for, in exactly
          the intermittent-failure case this fallback is here to survive. The same wipe would
          reset stuck-pending detection.
        * It never stamps ``_last_state``, which is the toast machine's memory of the last *real*
          reading. Stamping would fire a false "Engine running" balloon on recovery from a
          transient failure, swallow the real "Engine stopped" balloon when a failed tick lands
          between RUNNING and STOPPED, and spend the first-reading no-toast exemption.

        It carries no toast of its own: ``transition_toast`` has no ``-> UNKNOWN`` rule, so there
        is nothing to suppress here. :func:`~messagefoundry.tray.state.derive_state` already
        reduces an unqueryable SCM with both probes dark to
        :data:`~messagefoundry.tray.state.TrayState.UNKNOWN`, so the reducer needs no failure case
        of its own.

        The accepted cost: holding the anchors means a failed tick is a blind window, and a
        service that restarts entirely inside one leaves ``running_since`` pointing at the
        *previous* run, so the first tick after it can read WEDGED while the engine is really
        just booting. That is the better trade in both directions -- it self-corrects on the next
        tick once ``/health`` answers, whereas clearing the anchors defeats stuck detection for
        as long as the failures continue.
        """
        return PollResult(
            snapshot=self._build_snapshot(_UNKNOWN_STATE, _UNKNOWN_INPUTS),
            inputs=_UNKNOWN_INPUTS,
            reading=_UNKNOWN_READING,
        )

    def _build_result(self, inputs: ProbeInputs, reading: ScmReading, now: float) -> PollResult:
        state = derive_state(inputs)
        toast = self._maybe_toast(state, now)  # reads _last_state, so it must precede the stamp
        self._last_state = state
        return PollResult(
            snapshot=self._build_snapshot(state, inputs),
            inputs=inputs,
            reading=reading,
            toast=toast,
        )

    def _build_snapshot(self, state: TrayState, inputs: ProbeInputs) -> StatusSnapshot:
        """The render model for a derived state. Pure with respect to the poller's own memory."""
        return StatusSnapshot(
            state=state,
            service_name=self._config.service_name,
            engine_url=self._config.engine_url,
            console_enabled=inputs.ui is UiProbe.ENABLED,
            monitor_only=self._config.monitor_only,
        )

    def _maybe_toast(self, state: TrayState, now: float) -> Toast | None:
        """A transition toast, if warranted and not inside the rate-limit window."""
        if self._last_state is None:
            return None  # never toast on the very first reading (startup)
        candidate = transition_toast(self._last_state, state)
        if candidate is None:
            return None
        if (
            self._last_toast_at is not None
            and (now - self._last_toast_at) < self._toast_min_interval_s
        ):
            return None
        self._last_toast_at = now
        return candidate
