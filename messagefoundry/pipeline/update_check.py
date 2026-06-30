# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""No-network MessageFoundry version-update check (#30, ADR 0026 §1).

The MVP — and the only thing built — is a passive, **zero-egress** "pinned-vs-current" diff: it compares
the running :data:`messagefoundry.__version__` against the version recorded in the **installed
distribution metadata** (``importlib.metadata.version("messagefoundry")``). No PyPI call, no DNS, no
socket — the comparison reads metadata already present in the install. The result (``current_version`` /
``pinned_version`` / a derived ``update_available`` bool) carries **only version strings** — no message
content, no dependency list, no host data.

:class:`UpdateCheckRunner` clones the established background-monitor pattern of
:class:`~messagefoundry.pipeline.cert_expiry.CertExpiryRunner` /
:class:`~messagefoundry.pipeline.retention.RetentionRunner`: a small, engine-owned, cooperatively-
cancellable task whose ``run_once`` is a deterministic test seam (the loop only governs cadence). On a
diff it raises one advisory ``update_available`` AlertSink event and stores the latest result so the
``/status`` field can read it. The live-egress path (ADR 0026 §2) is **not** built here.

Engine-side and dependency-light (stdlib + the alert/version seams only), so it never pulls the API or
console into the engine and adds no new dependency.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from importlib import metadata

from messagefoundry import __version__
from messagefoundry.config.settings import UpdateCheckSettings
from messagefoundry.pipeline.alerts import AlertSink, LoggingAlertSink

__all__ = ["UpdateCheckResult", "UpdateCheckRunner", "compare_versions"]

log = logging.getLogger(__name__)

#: The package whose version is compared (the running engine), used as the alert/"connection" label.
PACKAGE_NAME = "messagefoundry"


@dataclass(frozen=True)
class UpdateCheckResult:
    """The outcome of one no-network version diff (#30). Carries only version strings (no PHI)."""

    current_version: str
    pinned_version: str | None  # None when the installed-distribution metadata can't be read
    update_available: bool


def _parse_release(version: str) -> tuple[int, ...]:
    """Parse the numeric *release* segment of a PEP 440-ish version into an int tuple for ordering.

    Stdlib-only (no ``packaging`` dependency, per ADR 0026 §1): split on a pre-release/build separator
    (``-``/``+``/``a``/``b``/``rc``/dev marker) and read the leading dotted numeric part. Non-numeric or
    empty components are treated as 0, so a malformed version sorts low rather than raising. This is a
    deliberately tolerant comparator: it orders the release tuple (``0.2.9`` < ``0.3.0``) and ignores
    pre-release ordering — adequate for "is the running build older than the pinned one"."""
    # Cut at the first character that begins a non-release segment (epoch is rare; ignored).
    head = version.strip()
    for sep in ("+", "-"):
        head = head.split(sep, 1)[0]
    # Stop the release run at the first non-(digit|dot) char (e.g. the 'a'/'b'/'rc'/'.dev' marker).
    release_chars: list[str] = []
    for ch in head:
        if ch.isdigit() or ch == ".":
            release_chars.append(ch)
        else:
            break
    parts = "".join(release_chars).split(".")
    out: list[int] = []
    for part in parts:
        try:
            out.append(int(part))
        except ValueError:
            out.append(0)
    return tuple(out) or (0,)


def compare_versions(current: str, pinned: str) -> int:
    """Return -1/0/1 for ``current`` <, ==, or > ``pinned`` by release tuple (stdlib-only).

    Shorter tuples are right-padded with zeros so ``0.2`` == ``0.2.0``. Tolerant of malformed input
    (a bad component sorts as 0) so the diff never raises on an odd version string."""
    cur, pin = _parse_release(current), _parse_release(pinned)
    width = max(len(cur), len(pin))
    cur += (0,) * (width - len(cur))
    pin += (0,) * (width - len(pin))
    if cur < pin:
        return -1
    if cur > pin:
        return 1
    return 0


def installed_pinned_version() -> str | None:
    """The version this install pins, from the installed distribution metadata (zero egress).

    Returns ``None`` in a source/checkout run where ``messagefoundry`` isn't installed as a distribution
    (no metadata) — the diff then reports ``update_available=False`` (nothing to compare against)."""
    try:
        return metadata.version(PACKAGE_NAME)
    except metadata.PackageNotFoundError:
        return None


class UpdateCheckRunner:
    """Periodically runs the no-network version diff and raises an ``update_available`` alert when the
    running build is older than the installed/pinned one. Construct with the ``[update_check]`` settings;
    call :meth:`start`/:meth:`stop` for the supervised loop, or :meth:`run_once` for a single
    deterministic pass (tests). :attr:`latest` exposes the most recent result for the ``/status`` field."""

    def __init__(
        self,
        settings: UpdateCheckSettings,
        *,
        alert_sink: AlertSink | None = None,
        clock: Callable[[], float] = time.time,
        current_version: str = __version__,
        pinned_source: Callable[[], str | None] = installed_pinned_version,
    ) -> None:
        self._settings = settings
        # Default to the logging sink so an available update is at least visible without a notifier.
        self._alert_sink: AlertSink = alert_sink or LoggingAlertSink()
        self._clock = clock
        self._current_version = current_version
        # Injected so tests can drive the "pinned" side without an install (and a future live mode can
        # swap in a hardened, env-clamped egress source — ADR 0026 §2 — without touching the loop).
        self._pinned_source = pinned_source
        self._latest: UpdateCheckResult | None = None
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

    @property
    def enabled(self) -> bool:
        """True when ``[update_check].enabled``. When False, :meth:`start` spawns no task and
        :attr:`latest` stays ``None`` (no ``/status`` field, no alert) — off-switch byte-identical."""
        return self._settings.enabled

    @property
    def latest(self) -> UpdateCheckResult | None:
        """The most recent :class:`UpdateCheckResult`, or ``None`` before the first pass / when disabled.
        Read by the ``/status`` endpoint to surface the additive update field."""
        return self._latest

    # --- lifecycle -----------------------------------------------------------

    def start(self) -> None:
        """Spawn the supervised diff loop (no-op when disabled)."""
        if self._task is not None:
            return
        if not self.enabled:
            log.debug("update check disabled ([update_check].enabled=false); not starting")
            return
        self._stop.clear()
        # Run one pass immediately so /status has a result without waiting a full interval.
        self.run_once()
        self._task = asyncio.create_task(self._run())
        log.info(
            "update check enabled (no-network local diff; every %gs)",
            self._settings.check_interval_seconds,
        )

    async def stop(self) -> None:
        """Signal the loop and await its exit (idempotent)."""
        self._stop.set()
        task = self._task
        self._task = None
        if task is not None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    async def _run(self) -> None:
        # One isolated pass per interval; an error in a pass is logged and the loop continues (a version
        # diff must never take the engine down). Cooperatively cancellable via _stop.
        while not self._stop.is_set():
            await self._sleep(self._settings.check_interval_seconds)
            if self._stop.is_set():
                break
            try:
                self.run_once()
            except Exception:
                log.exception("update check failed; will retry next interval")

    async def _sleep(self, delay: float) -> None:
        """Sleep up to ``delay``, waking immediately on stop (so shutdown isn't held by the interval)."""
        try:
            await asyncio.wait_for(self._stop.wait(), delay)
        except asyncio.TimeoutError:
            pass

    # --- one pass ------------------------------------------------------------

    def run_once(self) -> UpdateCheckResult:
        """Run the no-network diff once: compare the running version against the installed/pinned one,
        store the result for ``/status``, and emit a single ``update_available`` alert when the running
        build is older. Synchronous (metadata read only — no I/O that blocks meaningfully) and pure of
        side effects beyond the (best-effort) alert + the stored result. Never raises on a sink error."""
        pinned = self._pinned_source()
        update_available = pinned is not None and (
            compare_versions(self._current_version, pinned) < 0
        )
        result = UpdateCheckResult(
            current_version=self._current_version,
            pinned_version=pinned,
            update_available=update_available,
        )
        self._latest = result
        if update_available and pinned is not None:
            # The sink contract is never-raise, but be defensive — an alert failure must not abort the
            # pass that produced it (and the /status field stays authoritative regardless).
            try:
                self._alert_sink.update_available(
                    PACKAGE_NAME,
                    current_version=self._current_version,
                    pinned_version=pinned,
                )
            except Exception:
                log.warning("update_available alert sink failed", exc_info=True)
        return result
