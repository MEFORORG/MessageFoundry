# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""AES-GCM invocation-bound checkpointer + exhaustion alarm (ASVS 11.3.4).

Two jobs, one small background task modelled on
:class:`~messagefoundry.pipeline.cert_expiry.CertExpiryRunner`:

1. **Checkpoint the reserve.** ``AesGcmCipher.encrypt`` is synchronous and runs inside the store's write
   lock, so it cannot itself write to the DB. It spends from a pre-reserved block instead; this runner
   tops the block up asynchronously, one DB round trip per ~2**15 encrypts. Because the reservation is
   durable *before* the encrypts happen, an unclean exit can only ever over-count.

   The refill is **demand-driven**: the cipher fires a hook the moment its reserve crosses the half-block
   watermark and this runner wakes on it, so the interval below is a FLOOR (it still drives the alert
   pass on an idle engine), not the refill cadence. A fixed poll alone would quietly lose the
   reserve-leads-spend guarantee above ``block / interval`` encrypts per second — ~6.5k/s here, which is
   inside the product's own design envelope once a burst (rotation, an at-rest migration) is running.
2. **Alarm on exhaustion.** Once the key's persisted cumulative total crosses 2**31 — half the AES-GCM
   birthday ceiling — raise a routable ``gcm_invocations`` alert, so key exhaustion is *alerted* rather
   than calendar-hoped. Crossing 2**32 makes ``encrypt`` fail closed, and no write path catches
   ``CipherError``, so this alert is the operator's warning that ingest will stop if the key is not
   rotated. The realert throttle in the notifier sink bounds repeat pages.

**Why here and not in ``store/``.** ``store/`` imports nothing from ``pipeline/`` (CLAUDE.md §4), so the
store cannot reach the AlertSink; it exposes ``checkpoint_cipher_invocations`` and this engine-side
runner does the alerting. Same split as ``RetentionRunner``/``CertExpiryRunner``.

**Not leader-gated.** Every process spends its own reserved blocks, so every process must refill its own
— a leader-only checkpointer would let a follower shard overspend indefinitely.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable

from messagefoundry.pipeline.alerts import AlertSink, LoggingAlertSink
from messagefoundry.store.base import Store
from messagefoundry.store.crypto import (
    _GCM_MAX_INVOCATIONS,
    _GCM_SOFT_WARN_INVOCATIONS,
    AesGcmCipher,
)
from messagefoundry.store.gcm_bound import bounded_cipher

__all__ = ["GcmInvocationRunner"]

log = logging.getLogger(__name__)

#: Idle cadence — the FLOOR, not the refill mechanism (the cipher's refill hook wakes this loop the
#: moment the reserve crosses its watermark). It bounds how long an idle engine can sit on a key that
#: crossed 2**31 in another process before this one alerts. Deliberately a constant, not config.
_CHECKPOINT_INTERVAL_SECONDS = 10.0

#: The label carried as the alert's ``name`` (it stands in for "connection" in the throttle/subject).
_KEY_LABEL = "store data-encryption key"


class GcmInvocationRunner:
    """Periodically checkpoints the store cipher's invocation reserve and alerts near the ceiling."""

    def __init__(
        self,
        store: Store,
        *,
        alert_sink: AlertSink | None = None,
        interval_seconds: float = _CHECKPOINT_INTERVAL_SECONDS,
        warn_at: int = _GCM_SOFT_WARN_INVOCATIONS,
        ceiling: int = _GCM_MAX_INVOCATIONS,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._store = store
        # Default to the logging sink so an exhausting key is at least visible without a notifier.
        self._alert_sink: AlertSink = alert_sink or LoggingAlertSink()
        self._interval = interval_seconds
        self._warn_at = warn_at
        self._ceiling = ceiling
        self._clock = clock
        self._stop = asyncio.Event()
        #: Set by the cipher's refill hook when its reserve crosses the watermark — the demand signal
        #: this loop waits on alongside `_stop`.
        self._refill = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

    # --- lifecycle -----------------------------------------------------------

    def _bound(self) -> AesGcmCipher | None:
        """This store's bounded cipher, or ``None`` (identity / ``vault_transit``).

        Tolerant of a store object that does not implement ``cipher()`` at all — the engine starts this
        runner unconditionally, and an advisory counter must never be the thing that breaks an embedder
        or a partial test double. Such a store simply gets no demand-driven refill; the periodic
        checkpoint, which goes through the store's own ``checkpoint_cipher_invocations``, is unaffected."""
        getter = getattr(self._store, "cipher", None)
        return bounded_cipher(getter()) if callable(getter) else None

    def start(self) -> None:
        """Spawn the supervised checkpoint loop and arm the demand-driven refill signal (idempotent)."""
        if self._task is not None:
            return
        self._stop.clear()
        self._refill.clear()
        loop = asyncio.get_running_loop()
        bound = self._bound()
        if bound is not None:

            def _wake() -> None:
                # The hook fires on whichever thread encrypted (store writes are on the loop; the ADR
                # 0134 uploaded-logs store encrypts in a worker thread), so hop back onto the loop
                # thread-safely. `call_soon_threadsafe` raises once the loop is closed; the cipher
                # swallows that, and the engine unhooks at stop() anyway.
                loop.call_soon_threadsafe(self._refill.set)

            bound.set_refill_hook(_wake)
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        """Unhook the refill signal, signal the loop, await its exit, then SETTLE — squaring the key's
        persisted total with what this process actually spent, so a shutdown neither loses invocations
        the key performed nor permanently burns the unspent remainder of its reserved block. (The store's
        own ``close()`` settles too; both are idempotent, since a settlement zeroes the reserve.)"""
        bound = self._bound()
        if bound is not None:
            bound.set_refill_hook(None)
        self._stop.set()
        task = self._task
        self._task = None
        if task is not None:
            task.cancel()
            try:  # noqa: SIM105
                await task
            except asyncio.CancelledError:
                pass
        try:
            await self._store.checkpoint_cipher_invocations(settle=True)
        except Exception:  # noqa: BLE001 — shutdown best-effort; log and continue
            log.warning("could not settle the AES-GCM invocation bound at stop", exc_info=True)

    async def _run(self) -> None:
        # One isolated pass per interval; an error in a pass is logged and the loop continues (an
        # advisory counter must never take the engine down). Cooperatively cancellable via _stop.
        while not self._stop.is_set():
            try:
                await self.run_once()
            except Exception:
                log.exception("AES-GCM invocation checkpoint failed; will retry next interval")
            await self._sleep(self._interval)

    async def _sleep(self, delay: float) -> None:
        """Wait out the idle interval, but wake EARLY on either stop or a refill demand.

        Waiting on the bare interval is what let a high encrypt rate outrun the reserve: at more than
        ``block / delay`` encrypts per second the reserve is exhausted before the next pass, so the
        persisted total falls behind actual spend and an unclean exit under-counts."""
        waiters = [
            asyncio.ensure_future(self._stop.wait()),
            asyncio.ensure_future(self._refill.wait()),
        ]
        try:
            await asyncio.wait(waiters, timeout=delay, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for w in waiters:
                w.cancel()

    # --- one pass ------------------------------------------------------------

    async def run_once(self) -> int | None:
        """Checkpoint once and alert if over the soft threshold; returns the cumulative total (``None``
        when the store's cipher carries no bound — the identity cipher or ``vault_transit``). Pure enough
        to drive directly from a test; the loop only governs cadence."""
        # Clear BEFORE the checkpoint: a crossing that happens while it is in flight re-arms the signal
        # and the loop comes straight back round rather than sleeping on a stale-clear.
        self._refill.clear()
        total = await self._store.checkpoint_cipher_invocations()
        if total is None or total < self._warn_at:
            return total
        key_id = getattr(self._bound(), "active_key_id", "unknown")
        # The sink never raises (contract), but be defensive — a failing sink must not abort the loop.
        try:
            self._alert_sink.gcm_invocations(
                _KEY_LABEL, key_id=key_id, invocations=total, ceiling=self._ceiling
            )
        except Exception:
            log.warning("gcm_invocations alert sink failed", exc_info=True)
        return total
