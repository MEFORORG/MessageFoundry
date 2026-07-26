"""Pure engine-status state machine for the MessageFoundry tray (ADR 0113 §3).

No I/O, no ctypes, no Qt — stdlib only, so the whole reducer is unit-testable on any OS. The
shell (``winsvc``/``poller``) gathers the two credential-free probes — local SCM state and the
tokenless ``GET /health`` — and feeds them to :func:`derive_state`, which decides the single
:class:`TrayState` the icon, tooltip and menu render from.

The not-a-console boundary (ADR 0113 §2) is structural here: the probe inputs carry **no**
message body, queue depth, connection row, or throughput number, and :class:`StatusSnapshot`
is frozen against adding one (``tests/test_tray_boundary.py`` asserts the field set).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

# --- Timing constants (seconds). All grace/deadline math uses a MONOTONIC clock upstream
# (poller), so a laptop sleep/resume cannot mis-age a window (ADR 0113 §3). ---
BOOT_GRACE_S = 30.0
"""How long SCM may report RUNNING before ``/health`` answers without the tray calling it
WEDGED — an engine that just started (boot, NSSM auto-restart) needs a moment to bind."""

POLL_BASE_S = 5.0
POLL_PENDING_MIN_S = 1.0
POLL_PENDING_MAX_S = 10.0


class TrayState(Enum):
    """The single rendered status. Nine states so the tray can tell apart the failure modes an
    operator actually needs distinguished (ADR 0113 §3)."""

    NOT_INSTALLED = "not_installed"
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    RUNNING_UNMANAGED = "running_unmanaged"  # a dev `serve` on the port, not the NSSM service
    STOPPING = "stopping"
    WEDGED = "wedged"  # service RUNNING but /health dead past the boot grace
    FOREIGN = "foreign"  # the port answers, but not with a MessageFoundry /health body
    UNKNOWN = "unknown"  # SCM could not be queried and the API is not clearly up


class ScmState(Enum):
    """Local Service Control Manager state for the engine's NSSM service."""

    NOT_INSTALLED = "not_installed"
    STOPPED = "stopped"
    START_PENDING = "start_pending"
    STOP_PENDING = "stop_pending"
    RUNNING = "running"
    UNAVAILABLE = (
        "unavailable"  # SCM itself could not be queried (e.g. non-Windows, OpenSCM failed)
    )


class HealthProbe(Enum):
    """Outcome of the tokenless ``GET /health`` probe — liveness only, never a body field."""

    OK = "ok"  # 200 with a MessageFoundry Health shape ({"status": "ok", ...})
    FOREIGN = "foreign"  # answered, but the body is not a MessageFoundry /health payload
    DOWN = "down"  # no answer at all (connection refused / timeout)


class UiProbe(Enum):
    """Whether the web console (``/ui``) is mounted, from a tokenless probe (ADR 0113 §5).

    ``serve_ui`` off ⇒ ``/ui`` returns 404 ⇒ :data:`DISABLED`; on ⇒ 303→``/ui/login`` ⇒
    :data:`ENABLED`. Drives the "Open Monitor Console" menu item.
    """

    ENABLED = "enabled"
    DISABLED = "disabled"
    UNKNOWN = "unknown"  # not probed yet, or the engine is down


@dataclass(frozen=True)
class ProbeInputs:
    """Everything :func:`derive_state` needs — all credential-free, all boundary-clean."""

    scm: ScmState
    health: HealthProbe
    ui: UiProbe = UiProbe.UNKNOWN
    # Monotonic seconds since SCM was first observed RUNNING this run (None when not running);
    # grants the boot grace before a running-but-silent engine is called WEDGED.
    running_elapsed_s: float | None = None
    # True while a pending service's dwCheckPoint is still advancing within dwWaitHint.
    checkpoint_advancing: bool = True
    # Monotonic seconds spent in the current pending state (for stuck-pending detection).
    pending_elapsed_s: float | None = None
    wait_hint_s: float | None = None  # the service's reported dwWaitHint, in seconds


@dataclass(frozen=True)
class StatusSnapshot:
    """The complete render model — deliberately free of any workload data (ADR 0113 §2).

    ``tests/test_tray_boundary.py`` asserts these field names carry no
    message/queue/connection/count/rate field: the not-a-console boundary is mechanical, the
    same trick the IDE uses for ``ENGINE_LINK_FIELDS``. Do not add a field here without a new ADR.
    """

    state: TrayState
    service_name: str
    engine_url: str
    console_enabled: bool  # from the /ui probe → enables "Open Monitor Console"
    monitor_only: bool  # remote/https engine → service control + Open-Repo disabled (ADR 0113 §5)


def _pending_stuck(p: ProbeInputs) -> bool:
    """A pending service is stuck if it has waited longer than its own reported wait-hint."""
    if p.wait_hint_s is None or p.pending_elapsed_s is None:
        return False
    return p.pending_elapsed_s > max(p.wait_hint_s, 1.0)


def derive_state(p: ProbeInputs) -> TrayState:
    """Reduce the two probes to one :class:`TrayState`. Pure; no clock read of its own."""
    scm = p.scm

    # SCM unqueryable: fall back to whatever the API probe can tell us.
    if scm is ScmState.UNAVAILABLE:
        if p.health is HealthProbe.OK:
            return TrayState.RUNNING_UNMANAGED
        if p.health is HealthProbe.FOREIGN:
            return TrayState.FOREIGN
        return TrayState.UNKNOWN

    # No service registered: a live API on the port is a dev `serve`, not the service.
    if scm is ScmState.NOT_INSTALLED:
        if p.health is HealthProbe.OK:
            return TrayState.RUNNING_UNMANAGED
        if p.health is HealthProbe.FOREIGN:
            return TrayState.FOREIGN
        return TrayState.NOT_INSTALLED

    if scm is ScmState.STOP_PENDING:
        return TrayState.STOPPING

    if scm is ScmState.START_PENDING:
        if not p.checkpoint_advancing and _pending_stuck(p):
            return TrayState.WEDGED
        return TrayState.STARTING

    if scm is ScmState.STOPPED:
        # Service stopped but something still serves the API → a dev engine (or a squatter).
        if p.health is HealthProbe.OK:
            return TrayState.RUNNING_UNMANAGED
        if p.health is HealthProbe.FOREIGN:
            return TrayState.FOREIGN
        return TrayState.STOPPED

    if scm is ScmState.RUNNING:
        if p.health is HealthProbe.OK:
            return TrayState.RUNNING
        if p.health is HealthProbe.FOREIGN:
            return TrayState.FOREIGN
        # /health down while SCM RUNNING: within the boot grace it is still coming up.
        if p.running_elapsed_s is not None and p.running_elapsed_s < BOOT_GRACE_S:
            return TrayState.STARTING
        return TrayState.WEDGED

    return TrayState.UNKNOWN


def next_poll_seconds(state: TrayState, wait_hint_s: float | None = None) -> float:
    """Poll cadence for the next tick: fast while a service transition is in flight (Microsoft's
    ``waitHint/10`` guidance, clamped), otherwise the base cadence."""
    if state in (TrayState.STARTING, TrayState.STOPPING):
        hint = (wait_hint_s / 10.0) if wait_hint_s else POLL_BASE_S
        return max(POLL_PENDING_MIN_S, min(POLL_PENDING_MAX_S, hint))
    return POLL_BASE_S


@dataclass(frozen=True)
class Toast:
    """A rare, transition-only balloon (ADR 0113 §3). Rate-limiting is the poller's job; which
    transitions warrant a toast is decided here, purely."""

    title: str
    body: str


def transition_toast(old: TrayState, new: TrayState) -> Toast | None:
    """The toast (if any) for an ``old → new`` transition. Transient pending states never toast."""
    if old == new:
        return None
    if new is TrayState.RUNNING:
        return Toast("MessageFoundry", "Engine running")
    if new is TrayState.STOPPED and old in (
        TrayState.RUNNING,
        TrayState.RUNNING_UNMANAGED,
        TrayState.STOPPING,
        TrayState.WEDGED,
    ):
        return Toast("MessageFoundry", "Engine stopped")
    if new is TrayState.WEDGED:
        return Toast("MessageFoundry", "Engine unreachable — service up, API not responding")
    return None


_TOOLTIPS = {
    TrayState.NOT_INSTALLED: "service not installed",
    TrayState.STOPPED: "engine stopped",
    TrayState.STARTING: "engine starting…",
    TrayState.RUNNING: "engine running",
    TrayState.RUNNING_UNMANAGED: "engine running (not the Windows service)",
    TrayState.STOPPING: "engine stopping…",
    TrayState.WEDGED: "service up, API not responding",
    TrayState.FOREIGN: "another program answers on this port",
    TrayState.UNKNOWN: "status unknown",
}


def tooltip(state: TrayState) -> str:
    """The tray tooltip for a state (the icon's accessible name). Bounded to Shell's 128 chars."""
    return f"MessageFoundry – {_TOOLTIPS[state]}"[:128]
