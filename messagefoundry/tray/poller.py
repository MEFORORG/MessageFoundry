# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Background status poller for the tray (ADR 0113 §3).

A single daemon thread ticks every few seconds: read the local SCM state, probe the tokenless
``/health`` and ``/ui``, derive the :class:`~messagefoundry.tray.state.TrayState`, and hand a :class:`PollResult`
to the shell's update callback (which repaints the icon on the UI thread). The cadence tightens
to ``waitHint/10`` while a service transition is in flight.

The timing that turns raw readings into :class:`~messagefoundry.tray.state.ProbeInputs` — the boot-grace clock and
stuck-pending detection — is the **pure** :func:`advance`, keyed to a **monotonic** ``now`` so a
laptop sleep/resume cannot mis-age a window. Toast emission is transition-only and rate-limited.
All the stateful logic is dependency-injected (SCM reader, probes, clock) so it is unit-testable
without a real service or network.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

import httpx

from messagefoundry.tray.config import TrayConfig
from messagefoundry.tray.probe import make_probe_client, probe_health, probe_ui
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


@dataclass(frozen=True)
class Tracking:
    """Cross-tick memory the pure :func:`advance` carries forward (monotonic timestamps)."""

    running_since: float | None = None  # when SCM was first seen RUNNING this run
    pending_since: float | None = None  # when the current pending state was entered
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
    auto-restart does not flash WEDGED.
    """
    st = reading.state
    prev = tracking.last_scm

    running_since = (
        (tracking.running_since if prev is ScmState.RUNNING else now)
        if st is ScmState.RUNNING
        else None
    )

    same_pending = st in _PENDING and prev is st
    pending_since = (tracking.pending_since if same_pending else now) if st in _PENDING else None

    if same_pending and tracking.last_checkpoint is not None:
        checkpoint_advancing = reading.checkpoint > tracking.last_checkpoint
    else:
        checkpoint_advancing = True  # a freshly-entered pending state is assumed to be progressing

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
        client_factory: Callable[[str], httpx.Client] = make_probe_client,
        clock: Callable[[], float] = time.monotonic,
        toast_min_interval_s: float = TOAST_MIN_INTERVAL_S,
    ) -> None:
        self._config = config
        self._on_update = on_update
        self._scm_reader = scm_reader
        self._health_probe = health_probe
        self._ui_probe = ui_probe
        self._client_factory = client_factory
        self._clock = clock
        self._toast_min_interval_s = toast_min_interval_s
        self._client: httpx.Client | None = None
        self._tracking = Tracking()
        self._last_state: TrayState | None = None
        self._last_toast_at: float | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._client = self._client_factory(self._config.engine_url)
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
            result = self.poll_once(self._clock())
            try:
                self._on_update(result)
            except Exception:  # a UI callback must never kill the poll loop (supervisory boundary)
                log.exception("tray status callback raised")
            interval = next_poll_seconds(result.snapshot.state, result.inputs.wait_hint_s)
            self._stop.wait(interval)

    def poll_once(self, now: float) -> PollResult:
        """Read all probes once and produce a :class:`PollResult`. Does I/O via the injected deps."""
        reading = self._scm_reader(self._config.service_name)
        client = self._client
        health = self._health_probe(client) if client is not None else HealthProbe.DOWN
        ui = self._ui_probe(client) if client is not None else UiProbe.UNKNOWN
        self._tracking, inputs = advance(self._tracking, reading, health, ui, now)
        return self._build_result(inputs, reading, now)

    def _build_result(self, inputs: ProbeInputs, reading: ScmReading, now: float) -> PollResult:
        state = derive_state(inputs)
        snapshot = StatusSnapshot(
            state=state,
            service_name=self._config.service_name,
            engine_url=self._config.engine_url,
            console_enabled=inputs.ui is UiProbe.ENABLED,
            monitor_only=self._config.monitor_only,
        )
        toast = self._maybe_toast(state, now)
        self._last_state = state
        return PollResult(snapshot=snapshot, inputs=inputs, reading=reading, toast=toast)

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
