# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Third-tier disaster-recovery standby activation/release (ADR 0048, #61).

:class:`DrCoordinator` is the manual, audited, RBAC-gated promotion/fail-back orchestrator for a
right-sized DR box. It owns the **decision + ordering**; it delegates the *VIP move* to the passive
ADR-0047 load balancer (with an optional ``takeover_hook`` belt-and-braces for non-LB topologies) and
the *backup/restore mechanic* to #60 / ADR 0049 (it **reuses** :func:`run_restore_verify`). The engine
owns the **priority-feed startup** half (the DR run-profile in
:class:`~messagefoundry.pipeline.wiring_runner.RegistryRunner`).

**Activation ordering is fixed (ADR 0048 — the no-fenced-but-dead-box guarantee).** :meth:`activate`:

1. **Cold-seed restore-verify (fail-closed, BEFORE any VIP step).** Verify the #60 ``.mfbak`` seed
   archive via :func:`run_restore_verify`. A ``KEY_MISMATCH`` (the DR site does not hold the matching
   DEK — env/external KeyProvider required, DPAPI is machine-bound) or a ``FAIL`` (undecryptable /
   integrity / row-count) **aborts** activation closed (clear error, never start against an
   unverified/plaintext store) and records a ``dr_activation_aborted`` audit row. A configured
   KeyProvider endpoint that is unreachable from the DR site within ``takeover_timeout_seconds`` is the
   same fail-closed abort (AC-14), distinct from the in-archive decrypt failure (AC-9). Verifying the
   archive is not loading it — the restore is the operator's separate ``messagefoundry restore`` step —
   so activation then **also** refuses when the DR store does not carry the verified seed
   (:meth:`DrCoordinator._verify_seeded_store`), rather than promoting onto an empty store.
2. **Recover the cold-restored store + start a NEW audit-chain segment.** ``reset_stale_inflight``
   recovers in-flight rows of every stage carried in the backup (AC-15), then a ``dr_seed`` marker
   (seed-marker genesis = source-snapshot SHA-256 + config/DEK fingerprints + the restored chain's tip
   hash) is recorded so the DR box starts a NEW, independently-verifiable chain segment rather than
   blindly extending the restored chain (the audit-chain-fork handling, ADR 0049 / 0041).
3. **Acquire-VIP-or-abort.** Run the optional ``takeover_hook`` (exit 0 = "VIP acquired"); on
   failure/timeout, **abort** + ``dr_activation_aborted``. For an ADR-0047 LB topology the passive LB is
   the fence (the DR box binds, the VIP follows) and the hook is omitted; binding the priority listeners
   is done by the engine callback in step 4.
4. **Begin serving under the DR run-profile.** The engine activates the run-profile (bind only the
   connections at priority >= ``[dr].priority_threshold``; the rest report ``status:"filtered"``) via
   the injected ``activate_profile`` callback, and a ``dr.activate`` audit row records the promotion,
   with the fields the optional ``profile_provenance`` callback returns. The engine's callback re-applies the graph
   it is already running and reads no config dir to do it (vault BACKLOG #3067), so a config dir that
   has gone with the failed site cannot refuse this step.

:meth:`release` is **drain-then-hand-back**: release the VIP (the optional ``release_hook`` / let the
passive LB return it to the recovered primary), wait for convergence, unbind intake while the workers
drain the staged queue (delivered/dead-lettered) — preserving at-least-once + idempotency **within the
DR store** — then record ``dr.release``. The drain is bounded, and rows held on outbounds the engine
parks are left out of it; ``dr.release`` records how many rows are left and how many are held. **Cross-store** reconciliation with the recovered
primary is operator-verified per the runbook (the engine gives NO cross-store loss/duplicate guarantee).

This module is engine-side and dependency-light (stdlib + the store/settings/dr_backup seams), so it
never pulls the API or console into the engine. The VIP hook runs OFF the event loop (a subprocess) so
it never blocks asyncio; **PHI is never logged** (only counts / paths / one-way fingerprints).
"""

from __future__ import annotations

import asyncio
import json
import logging
import socket
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

from messagefoundry import proctree
from messagefoundry.childenv import hook_environment
from messagefoundry.config.settings import DrSettings, StoreBackend
from messagefoundry.pipeline.alerts import AlertSink, LoggingAlertSink
from messagefoundry.pipeline.dr_backup import VerifyResult, run_restore_verify
from messagefoundry.pipeline.path_confine import confine, lexical_roots
from messagefoundry.redaction import safe_exc
from messagefoundry.store import Store
from messagefoundry.store.store import OwnedLanes

__all__ = ["DrCoordinator", "DrActivationError", "DrResult"]

log = logging.getLogger(__name__)

#: The audit actions this coordinator records (PHI-free). ``dr_seed`` is the cold-seed marker genesis
#: that opens a NEW audit-chain segment; ``dr.activate`` / ``dr.release`` bracket a promotion;
#: ``dr_activation_aborted`` records every refused activation with its (scrubbed) reason.
_ACTION_SEED = "dr_seed"
_ACTION_ACTIVATE = "dr.activate"
_ACTION_RELEASE = "dr.release"
_ACTION_ABORTED = "dr_activation_aborted"
#: A release that did not hand back: its drain raised, or it was cancelled partway (vault BACKLOG
#: #2752). The box stays active and the release can be retried. Kept apart from ``dr.release``, which
#: only a completed hand-back writes, so a filter on that action still finds only fail-backs.
_ACTION_RELEASE_FAILED = "dr_release_failed"

#: The one answer for every refused request archive, whichever check refused it. It names the
#: setting and no part of the path, so the refusal says nothing about what exists on the DR box.
_REQUEST_ARCHIVE_REFUSED = (
    "the archive named in the request was refused: a request may name only an archive under "
    "[dr].seed_dir, and with [dr].seed_dir unset it may name none. Set [dr].seed_dir, or name "
    "the archive in [dr].seed_archive — refusing to activate (ADR 0048 fail-closed)"
)


class DrActivationError(RuntimeError):
    """Activation (or release) was refused. Carries a ``kind`` (at least ``seed``/``key``/``vip``/
    ``profile``/``state``/``audit``) so the caller (the API endpoint) can map it to an HTTP error and
    the operator sees the failing phase. ``audit`` is the one kind that is not an abort: the box's
    posture already changed and the audit row recording that could not be written, so the call
    refuses rather than answer success with no row (vault BACKLOG #2751, #2752). The message is
    ``safe_exc``-scrubbed (PHI-free)."""

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind


@dataclass(frozen=True)
class DrResult:
    """The PHI-free outcome of an activate/release — returned for the API response + tests. Paths,
    counts, one-way fingerprints, and a status only (never a body or key bytes)."""

    action: str  # "activate" | "release"
    active: bool  # whether the DR run-profile is now on
    threshold: str  # the [dr].priority_threshold value in effect
    archive: str | None = None  # the seed archive verified (activate only), filename-shaped
    verify_status: str | None = None  # the restore-verify result (PASS), activate only
    seed_segment: str | None = None  # the new audit-chain segment marker's own row hash digest
    vip_hook_ran: bool = False  # whether the optional takeover/release hook was invoked
    #: Release only: the staged-queue depth left when the drain ended (0 = drained), or ``None``
    #: when the engine callback reported none (vault BACKLOG #2752, finding D-V1).
    depth_left: int | None = None
    #: Release only: whether every DRAINABLE row drained. Rows held on outbounds the engine parks
    #: cannot drain, so the drain leaves them out and counts them in ``held_on_parked_outbounds``
    #: (vault BACKLOG #3067). ``None`` when the engine callback reported neither.
    drained: bool | None = None
    held_on_parked_outbounds: int | None = None


@dataclass
class _ActivationProgress:
    """How far one activation got, read by its cancellation arm (vault BACKLOG #2751)."""

    step: str = "seed"  # seed | store | vip | profile
    profile_applied: bool = False


class DrCoordinator:
    """Manual, audited DR promotion/fail-back (ADR 0048). Construct with the open store + ``[dr]``
    settings + the store settings (the KeyProvider seam for restore-verify) + two engine callbacks that
    flip the DR run-profile (``activate_profile`` re-applies the graph with the run-profile ON;
    ``deactivate_profile`` unbinds intake + drains, then turns it OFF, and returns the drain's
    outcome fields for the ``dr.release`` row), and optional callbacks for the seed marker's config
    digest, for provenance fields on the ``dr.activate`` row, and for cleanup after a recorded
    release. Single-writer: the API serializes
    activate/release behind ``[approvals]``-style RBAC; this object additionally guards against a
    concurrent activate/release with its own lock."""

    def __init__(
        self,
        store: Store,
        settings: DrSettings,
        *,
        store_settings: object,
        activate_profile: Callable[[], Awaitable[None]],
        deactivate_profile: Callable[[], Awaitable[Mapping[str, object] | None]],
        config_fingerprint_provider: Callable[[], Awaitable[str | None]] | None = None,
        alert_sink: AlertSink | None = None,
        clock: Callable[[], float] = time.time,
        owned_lanes: Callable[[], OwnedLanes | None] | None = None,
        profile_provenance: Callable[[], Awaitable[Mapping[str, object]]] | None = None,
        after_release: Callable[[], Awaitable[None]] | None = None,
    ) -> None:
        self._store = store
        self._settings = settings
        # The store settings carry the KeyProvider seam (ADR 0019) — the DEK the cold-seed archive is
        # encrypted under. Typed loosely to avoid importing StoreSettings here; run_restore_verify takes it.
        self._store_settings = store_settings
        self._activate_profile = activate_profile
        # Extra fields for the dr.activate row, such as the activated graph's digest. Awaited after
        # the profile is applied; a fault is recorded on the row and never fails the activation.
        self._provenance = profile_provenance
        self._deactivate_profile = deactivate_profile
        # Cleanup a completed hand-back still owes, such as closing the parked outbounds' sessions.
        # Awaited once the box has handed back, after the attempt to write the dr.release row,
        # whether or not that write lands. Its errors are logged, so nothing it does can fail the
        # release or leave it half recorded (vault BACKLOG #3263).
        self._after_release = after_release
        # Awaited per activation, so building the coordinator reads no file (vault BACKLOG #2839).
        self._config_fingerprint_provider = config_fingerprint_provider
        self._alert_sink: AlertSink = alert_sink or LoggingAlertSink()
        # #145: the DR box label carried in dr_activated / dr_released alerts (also the throttle /
        # auto-resolve key). The hostname is stable across an activate/release pair (same box), so the
        # fail-back resolves the promotion instance. PHI-free (a host label only).
        self._node = socket.gethostname()
        self._clock = clock
        # ADR 0073: the engine's ownership scope for the activation recovery reset. On a SHARDED DR
        # fleet the shards activate one by one against the SAME restored store, so a global reset on
        # the second activation would re-pend rows the first is already mid-processing — the exact
        # cross-shard clobber the scoped startup reset removes. None/None-returning = global (the
        # unsharded DR box, where "no live siblings" genuinely holds).
        self._owned_lanes = owned_lanes
        # Whether the DR run-profile is currently on (mirrors the engine's _dr_active; the engine seeds
        # it from [dr].activate at construction and this coordinator flips it on activate/release).
        self._active = bool(settings.enabled and settings.activate)
        # An activation whose run-profile is applied but whose dr.activate row is not yet known to be
        # written: (detail, actor, now). Set before the write and cleared after it, so a write that a
        # cancellation or a store error cut short is written by the next activate or release call
        # rather than that call answering success with no row (vault BACKLOG #2751). Held in memory
        # only, so a restart loses it; the refusal and its log line are what record that. A box active
        # from [dr].activate at boot never set it: that activation is the configuration's.
        self._unrecorded_activation: tuple[dict[str, object], str, float] | None = None
        # The same for a completed hand-back whose dr.release row is not yet known to be written
        # (vault BACKLOG #2752). The next activate or release call writes it first.
        self._unrecorded_release: tuple[dict[str, object], str, float] | None = None
        # The last completed hand-back, so a retry that finds the box passive answers with that
        # release's outcome (its depth left) rather than with nothing known.
        self._last_release: DrResult | None = None
        # Serialize activate/release so a double-promotion can't race the cold-seed/VIP/profile steps.
        self._lock = asyncio.Lock()

    @property
    def active(self) -> bool:
        """Whether the DR run-profile is currently on (the box is serving the critical feeds)."""
        return self._active

    @property
    def settings(self) -> DrSettings:
        return self._settings

    # --- activate ------------------------------------------------------------

    async def activate(
        self,
        *,
        archive: str | None = None,
        dba_attests_restored: bool = False,
        actor: str = "system",
    ) -> DrResult:
        """Promote this DR box (ADR 0048 fixed ordering: cold-seed restore-verify → new audit segment →
        acquire-VIP-or-abort → serve under the DR run-profile). MANUAL only — there is no auto-probe in
        this slice; the caller (``POST /dr/activate``) is RBAC-gated by ``dr:operate`` and supplies the
        operator ``actor`` for the audit rows.

        ``archive`` overrides ``[dr].seed_archive`` (the runbook may pass the chosen #60 backup in the
        request body), and is confined to ``[dr].seed_dir`` before anything opens it
        (:meth:`_confine_request_archive`). ``dba_attests_restored`` is the operator's explicit, per-activation attestation that
        a DBA has restored the server-DB ``mefor`` database for THIS failover — REQUIRED on a
        Postgres/SQL Server store (the config-only cold-seed archive cannot restore or verify a
        DBA-managed DB) and IGNORED on SQLite (BACKLOG #102). Raises :class:`DrActivationError` and records
        a ``dr_activation_aborted`` audit row on any abort; never leaves the VIP held against a store that
        will not open (the restore-verify fail-closes BEFORE the VIP step)."""
        if self._settings.enabled is False:
            # Not a DR box at all — activation is meaningless. Fail loud rather than silently no-op.
            raise DrActivationError(
                "state",
                "this deployment is not a DR standby ([dr].enabled is false); activation is not available",
            )
        async with self._lock:
            if self._active:
                # Idempotent: already serving the critical feeds. Report the current posture rather than
                # re-running the cold seed (which would re-verify + re-mark — wasteful and confusing).
                # But never as success for an activation with no dr.activate row: write the one a
                # cut-short activation owes first, or refuse (vault BACKLOG #2751).
                if self._unrecorded_activation is not None:
                    await self._record_owed_activation()
                return DrResult(
                    action="activate",
                    active=True,
                    threshold=self._settings.priority_threshold.value,
                )
            # A hand-back still owed its row is recorded before a new promotion can follow it.
            if self._unrecorded_release is not None:
                await self._record_owed_release()
            now = self._clock()
            progress = _ActivationProgress()
            try:
                return await self._activate_locked(
                    archive=archive,
                    dba_attests_restored=dba_attests_restored,
                    actor=actor,
                    now=now,
                    progress=progress,
                )
            except BaseException as exc:
                # A cancellation is not an Exception, so neither step 4's arm nor any abort path
                # sees one (vault BACKLOG #2751). The API runs activation so that a request
                # deadline does not cancel it (api/outlive.py); this arm is for what still can,
                # such as a shutdown. It puts the flag back unless the run-profile was applied,
                # records the outcome, and re-raises.
                if not isinstance(exc, Exception):
                    if not progress.profile_applied:
                        self._active = False
                    if isinstance(exc, asyncio.CancelledError):
                        await self._record_interrupted_activation(progress, actor, now)
                raise

    async def _activate_locked(
        self,
        *,
        archive: str | None,
        dba_attests_restored: bool,
        actor: str,
        now: float,
        progress: _ActivationProgress,
    ) -> DrResult:
        """Steps 1 to 4 of :meth:`activate`, run under its lock. ``progress`` records the step
        reached, for the cancellation arm there."""
        seed = archive or self._settings.seed_archive
        if archive:
            seed = await self._confine_request_archive(archive, actor, now)

        # (1) Cold-seed restore-verify — FAIL-CLOSED, BEFORE any VIP step (AC-9/AC-14). A missing
        # seed path is itself an abort: a DR box must never promote onto an unverified store.
        if not seed:
            await self._record_aborted(
                "seed",
                "no [dr].seed_archive configured and no archive supplied — refusing to activate "
                "without a restore-verified cold seed (ADR 0048 fail-closed)",
                actor,
                now,
            )
        verify = await self._verify_seed(seed, actor, now)

        # (1b) SERVER-DB LIVE SEED GATE (BACKLOG #102, fail-closed, BEFORE any store mutation or VIP
        # step). A config-only cold-seed archive (server-DB store) verifies only that the tar/config
        # decrypt — it NEVER restores or inspects the DBA-managed live ``mefor`` DB, so step (1) alone
        # could bless promotion against a fresh/unrestored server store (non-empty only because
        # provision-admin, engine startup and operator sign-in wrote to audit_log). Require an
        # explicit DBA attestation AND a restore-provenance probe here. No-op on SQLite (the
        # archive verified the whole store already).
        await self._verify_live_server_seed(dba_attests_restored, actor, now)

        # (1c) COLD-SEED *LOAD* GATE (fail-closed, BEFORE any store mutation or VIP step). Step (1)
        # proved the ARCHIVE is good; this proves the box's own store carries it. The SQLite twin of
        # the server-DB gate above.
        await self._verify_seeded_store(verify, actor, now)

        # (2) Recover the cold-restored store (every stage, AC-15) + open a NEW audit-chain segment
        # (the seed-marker genesis; do NOT blindly extend the restored chain — ADR 0049/0041).
        # Ownership-scoped when sharded (ADR 0073) — see _owned_lanes in __init__.
        progress.step = "store"
        try:
            await self._store.reset_stale_inflight(
                owned=self._owned_lanes() if self._owned_lanes is not None else None
            )
        except Exception as exc:  # a store that can't recover its own residue can't safely serve
            await self._record_aborted(
                "state",
                f"cold-restored store recovery (reset_stale_inflight) failed: {safe_exc(exc)}",
                actor,
                now,
            )
        seed_segment = await self._record_seed_marker(seed, verify, now)

        # (3) Acquire-VIP-or-abort (ADR 0048). The optional takeover_hook is belt-and-braces for a
        # non-LB topology; an ADR-0047 LB deployment omits it (the passive LB moves the VIP once the
        # listeners bind in step 4). A hook failure/timeout ABORTS before any listener serves the VIP.
        progress.step = "vip"
        hook_ran = await self._run_vip_hook(
            self._settings.takeover_hook, phase="takeover", actor=actor, now=now
        )

        # (4) Serve under the DR run-profile: bind only the connections at/above the threshold (the
        # rest report status:"filtered"). The engine re-applies its running graph with the
        # run-profile ON. A cancellation here is not an Exception and passes this arm; activate()'s
        # own arm puts the flag back, and the engine's reload rolls its intake back (vault BACKLOG
        # #2751).
        progress.step = "profile"
        try:
            self._active = True
            self._last_release = None  # an earlier fail-back's outcome no longer describes this box
            await self._activate_profile()
        except Exception as exc:
            self._active = False
            reason = (
                "DR run-profile activation failed (the engine could not bind the priority "
                f"feeds): {safe_exc(exc)}"
            )
            await self._record_aborted("profile", reason, actor, now)
        progress.profile_applied = True

        # Owed from here: a write cut short is made good by the next activate or release call.
        detail: dict[str, object] = {
            "archive": _basename(seed),
            "verify": verify.status,
            "threshold": self._settings.priority_threshold.value,
            "seed_segment": seed_segment,
            "vip_hook_ran": hook_ran,
        }
        self._unrecorded_activation = (detail, actor, now)
        # Provenance is read only once the profile is applied and the row is owed, so a cancellation
        # while it is read still leaves the box recorded as active (vault BACKLOG #3067). Its fields
        # never replace the coordinator's own.
        if self._provenance is not None:
            try:
                provenance = await self._provenance()
            except Exception as exc:
                # The profile is live, so a provenance fault must not fail the activation.
                log.warning("DR activation: could not read the provenance fields", exc_info=True)
                provenance = {"provenance_error": safe_exc(exc)}
            for key, value in provenance.items():
                detail.setdefault(key, value)
        await self._record_owed_activation(late=False)
        return DrResult(
            action="activate",
            active=True,
            threshold=self._settings.priority_threshold.value,
            archive=_basename(seed),
            verify_status=verify.status,
            seed_segment=seed_segment,
            vip_hook_ran=hook_ran,
        )

    # --- release (fail-back) -------------------------------------------------

    async def release(self, *, actor: str = "system") -> DrResult:
        """Fail back to the recovered primary — **drain-then-hand-back** (ADR 0048). Release the VIP (the
        optional ``release_hook`` / let the passive LB return it to the primary), then the engine unbinds
        all inbound listeners while the workers drain the staged queue to completion. Returns success only
        once the VIP is off the DR box and intake is unbound, so there is **no dual-accept window** while
        the VIP moves. **Within the DR store** at-least-once + idempotency are preserved on drain;
        **cross-store** reconciliation with the recovered primary is operator-verified per the runbook
        (the engine gives no cross-store loss/duplicate guarantee — documented, not an engine AC)."""
        async with self._lock:
            now = self._clock()
            if not self._active:
                try:
                    # Never success for a hand-back with no dr.release row: write the one a
                    # cut-short release owes first, or refuse (vault BACKLOG #2752).
                    if self._unrecorded_release is not None:
                        await self._record_owed_release()
                finally:
                    # A release whose row or cleanup was cut short never ran the cleanup, or not
                    # to its end. It is safe to repeat, so a retry finishes it, and does so
                    # whether or not the owed row lands now (vault BACKLOG #3263).
                    await self._run_after_release()
                return self._last_release or DrResult(
                    action="release",
                    active=False,
                    threshold=self._settings.priority_threshold.value,
                )
            # An activation still owed its row is recorded before the hand-back that ends it, or the
            # release is refused (vault BACKLOG #2751).
            if self._unrecorded_activation is not None:
                await self._record_owed_activation()
            # Release the VIP FIRST (so partners reconnect to the primary), then unbind intake + drain.
            # Order matters: the VIP must be off the DR box before — or as — intake stops, so no message
            # is dual-accepted while the VIP moves.
            phase = "release_hook"
            hook_ran = False
            detail: dict[str, object] = {}
            try:
                hook_ran = await self._run_vip_hook(
                    self._settings.release_hook, phase="release", actor=actor, now=now
                )
                phase = "drain"
                try:
                    # Unbind listeners and drain the staged queue. Its fields (the depth left, the
                    # drained verdict and the rows held on parked outbounds) go on the dr.release row.
                    drain = await self._deactivate_profile()
                except Exception as exc:
                    # A failed drain leaves the box active (still draining) — report it loudly, do NOT
                    # claim a clean hand-back (a half-drained release would risk cross-store divergence
                    # the runbook can't account for). The failure has its own row (vault BACKLOG #2752).
                    await self._record_release_failed(
                        "drain_failed", phase, hook_ran, actor, now, error=exc
                    )
                    raise DrActivationError(
                        "state",
                        f"DR release drain failed; the box stays active (retry release): {safe_exc(exc)}",
                    ) from exc
                phase = "record"
                self._active = False
                detail = _release_detail(hook_ran, drain)
                self._last_release = self._release_result(detail)
                # Owed from here: a write cut short is made good by the next activate or release.
                self._unrecorded_release = (detail, actor, now)
                try:
                    await self._record_owed_release(late=False)
                finally:
                    # The box has handed back, so it holds no partner session whether or not
                    # the row was written (vault BACKLOG #3262). A refused write still refuses
                    # the release, and the row stays owed. A cancellation of the cleanup is
                    # in the record phase, so the arm below does not read it as a failed
                    # release (vault BACKLOG #3263).
                    await self._run_after_release()
            except asyncio.CancelledError:
                # A cancellation is not an Exception, so the drain's arm above never sees one (vault
                # BACKLOG #2752). The API runs a release so that a request deadline does not cancel it
                # (api/outlive.py); this arm is for what still can, such as a shutdown. Before the
                # record step the box stays active, as for a failed drain, and the release can be
                # retried; it is never flipped to passive with intake still to account for.
                if phase == "record":
                    # The hand-back completed and only its row was cut short: write it late.
                    try:
                        await self._record_owed_release()
                    except DrActivationError:
                        log.warning(
                            "DR: an interrupted release handed back, and its dr.release row is "
                            "still owed; the next activate or release call writes it",
                            exc_info=True,
                        )
                else:
                    # After a drain failure whose own row was being written this may be a second
                    # row for one release; a duplicate is the safer of the two failures.
                    if phase == "release_hook":
                        # The hook was started, and a release hook is not killed (vault BACKLOG #2622).
                        hook_ran = bool(self._settings.release_hook)
                    await self._record_release_failed("interrupted", phase, hook_ran, actor, now)
                raise
            return self._release_result(detail)

    async def _run_after_release(self) -> None:
        """Run the engine's cleanup for a hand-back that is complete. An error is logged and not
        raised: the release stands, and a retried release or the next reload finishes it."""
        if self._after_release is None:
            return
        try:
            await self._after_release()
        except Exception:
            log.warning(
                "DR: the release handed back, but its cleanup did not finish; a retried release "
                "or the next reload closes any outbound session still open",
                exc_info=True,
            )

    def _release_result(self, detail: Mapping[str, object]) -> DrResult:
        """The :class:`DrResult` of a completed hand-back, read from its ``dr.release`` detail."""
        return DrResult(
            action="release",
            active=False,
            threshold=self._settings.priority_threshold.value,
            vip_hook_ran=detail.get("vip_hook_ran") is True,
            depth_left=_count(detail.get("depth_left")),
            drained=_flag(detail.get("drained")),
            held_on_parked_outbounds=_count(detail.get("held_on_parked_outbounds")),
        )

    # --- outcome rows for a cut-short activate or release (vault BACKLOG #2751, #2752) ---------

    async def _record_owed_activation(self, *, late: bool = True) -> None:
        """Write the ``dr.activate`` row for an activation whose run-profile is applied, then log and
        alert. ``late`` marks a row written by a later call than the one that activated (a retry, or
        the cancellation arm), and the row says so.

        A store error is a refusal, not a success: the activation stays owed, and the caller's
        request fails rather than answering success with no row. A cancellation that lands after
        the write committed can leave the row written twice, the second marked late; a duplicate is
        the safer of the two failures."""
        owed = self._unrecorded_activation
        if owed is None:
            return
        detail, actor, now = owed
        try:
            await self._store.record_audit(
                _ACTION_ACTIVATE,
                actor=actor,
                detail=json.dumps(
                    {**detail, **({"recorded_late": True} if late else {})},
                    sort_keys=True,
                    # The profile is live by now, so a callback field json cannot encode must
                    # not stop the row from being written.
                    default=str,
                ),
                now=now,
            )
        except Exception as exc:
            # Kind "audit" on every call, so the route answers 503 with this message rather than a
            # bare 500 that hides that the activation happened.
            raise DrActivationError(
                "audit",
                "this box is serving the DR run-profile, but the dr.activate audit row for that "
                "activation could not be written, so DR calls are refused until it is; retry once "
                f"the audit log accepts writes: {safe_exc(exc)}",
            ) from exc
        self._unrecorded_activation = None
        log.warning(
            "DR activated by %s: serving feeds at priority >= %s; cold seed %s verified %s "
            "(new audit-chain segment opened)%s",
            actor,
            detail["threshold"],
            detail["archive"],
            detail["verify"],
            " -- the dr.activate row was written late" if late else "",
        )
        # #145: page on the promotion — the primary is down and this box is now serving. Never-raise:
        # a sink failure must not undo a completed activation. dr_released is the auto-resolving inverse.
        self._alert_dr("dr_activated")

    async def _record_interrupted_activation(
        self, progress: _ActivationProgress, actor: str, now: float
    ) -> None:
        """The outcome row for an activation a cancellation cut short. Best-effort: it runs on the
        way out of a cancellation, so a store error is logged and the cancellation still raises.

        Once the run-profile is applied the box IS active, and what is owed is the ``dr.activate``
        row. Before that, the box stays passive and a ``dr_activation_aborted`` row of kind
        ``interrupted`` names the step reached; from the VIP step on, the takeover hook may have
        run, so the row says the address may have moved."""
        if progress.profile_applied:
            try:
                await self._record_owed_activation()
            except DrActivationError:
                log.warning(
                    "DR: an interrupted activation left the run-profile applied, and its dr.activate "
                    "row is still owed; the next activate or release call writes it",
                    exc_info=True,
                )
            return
        reason = f"activation interrupted during the {progress.step} step; the box stays passive"
        if progress.step in ("vip", "profile"):
            reason += (
                ". The takeover hook may have run, so the VIP may have moved to this box with no "
                "priority listener bound -- check the load balancer before retrying"
            )
        await self._write_aborted_row("interrupted", reason, actor, now)

    async def _record_release_failed(
        self,
        reason: str,
        phase: str,
        hook_ran: bool,
        actor: str,
        now: float,
        *,
        error: Exception | None = None,
    ) -> None:
        """A ``dr_release_failed`` row: the release did not hand back, and the box stays active.
        ``phase`` is how far it got (``release_hook`` or ``drain``). Best-effort, like
        :meth:`_write_aborted_row`: the refusal it records must still reach the caller."""
        detail: dict[str, object] = {"reason": reason, "phase": phase, "vip_hook_ran": hook_ran}
        if error is not None:
            detail["error"] = safe_exc(error)
        if phase == "release_hook":
            # A release hook is not killed when its caller is cancelled (_run_vip_hook, vault
            # BACKLOG #2622), so it may still hand the address back to the primary.
            detail["hook_left_running"] = hook_ran
        try:
            await self._store.record_audit(
                _ACTION_RELEASE_FAILED,
                actor=actor,
                detail=json.dumps(detail, sort_keys=True),
                now=now,
            )
        except Exception:
            log.warning("DR: could not record the dr_release_failed audit row", exc_info=True)
        log.warning(
            "DR release did not complete (%s during the %s phase); the box stays active -- retry "
            "the release%s",
            reason,
            phase,
            (
                ". The release hook was left running and may still move the VIP to the primary"
                if phase == "release_hook"
                else ""
            ),
        )

    async def _record_owed_release(self, *, late: bool = True) -> None:
        """Write the ``dr.release`` row for a hand-back that completed, then log and alert. The
        twin of :meth:`_record_owed_activation`, with the same ``late`` marking, the same refusal on
        a store error and the same possible duplicate."""
        owed = self._unrecorded_release
        if owed is None:
            return
        detail, actor, now = owed
        try:
            await self._store.record_audit(
                _ACTION_RELEASE,
                actor=actor,
                detail=json.dumps(
                    {**detail, **({"recorded_late": True} if late else {})},
                    sort_keys=True,
                    # The profile is live by now, so a callback field json cannot encode must
                    # not stop the row from being written.
                    default=str,
                ),
                now=now,
            )
        except Exception as exc:
            raise DrActivationError(
                "audit",
                "this box has handed back, but the dr.release audit row for that release could "
                "not be written, so DR calls are refused until it is; retry once the audit log "
                f"accepts writes: {safe_exc(exc)}",
            ) from exc
        self._unrecorded_release = None
        depth = detail.get("depth_left")
        held = detail.get("held_on_parked_outbounds")
        if detail.get("drained") is True and held:
            # Rows on outbounds the engine parks cannot drain on this box (vault BACKLOG #3067).
            # They stay PENDING with no attempt charged.
            log.warning(
                "DR released by %s: VIP handed back, intake unbound, every drainable row drained; "
                "%s row(s) stay held on parked outbounds until those outbounds come up — reconcile "
                "per the runbook",
                actor,
                held,
            )
        elif depth == 0:
            log.warning(
                "DR released by %s: VIP handed back, intake unbound, staged queue drained — the "
                "recovered primary resumes (cross-store reconciliation is operator-verified per the "
                "runbook)",
                actor,
            )
        elif depth is None:
            log.warning(
                "DR released by %s: VIP handed back, intake unbound; the drain reported no queue "
                "depth, so whether rows remain is unknown — reconcile per the runbook",
                actor,
            )
        else:
            # D-V1 (vault BACKLOG #2752): the drain gave up at its bound. Say so, and how many.
            # Held rows were never waited for, so they are not among those that did not drain.
            if isinstance(depth, int) and isinstance(held, int):
                depth = max(depth - held, 0)
            log.warning(
                "DR released by %s: VIP handed back, intake unbound, but %s staged row(s) did not "
                "drain within the bound and stay queued + replayable — reconcile them with the "
                "recovered primary per the runbook",
                actor,
                depth,
            )
        # #145: the inverse — auto-resolves the open dr_activated instance (no page on a clean fail-back).
        self._alert_dr("dr_released")

    # --- internals -----------------------------------------------------------

    async def _confine_request_archive(self, archive: str, actor: str, now: float) -> str:
        """The resolved path of a request-named ``archive``, or an abort if it is not under
        ``[dr].seed_dir`` (vault BACKLOG #2581). Deny by default: with ``seed_dir`` unset, a
        request may name no archive.

        :func:`~messagefoundry.pipeline.path_confine.confine` judges the text of ``archive`` first,
        with no filesystem call on it, then resolves, off the event loop. The caller verifies the
        RESOLVED path, so the file that was checked is the file that is opened. Every refusal
        aborts with one message, and the audit row alone records the path that was asked for.

        A ``seed_dir`` this box cannot resolve is a different answer: it is the operator's own
        directory that failed, so the abort says so and names no part of the request."""
        seed_dir = self._settings.seed_dir
        resolved: Path | None = None
        if seed_dir:
            timeout = self._settings.takeover_timeout_seconds
            try:
                resolved = await asyncio.wait_for(
                    asyncio.to_thread(_confined_archive, archive, seed_dir), timeout=timeout
                )
            except OSError as exc:
                # An unreachable share, say, or one that does not answer in time (TimeoutError is
                # an OSError). Still an abort with its audit row, never an unhandled error.
                log.warning(
                    "DR activation: could not resolve [dr].seed_dir for a request archive: %s",
                    safe_exc(exc),
                )
                await self._record_aborted(
                    "seed",
                    f"[dr].seed_dir could not be resolved from this box within {timeout:g}s, so "
                    "the archive named in the request was not checked — refusing to activate "
                    "(ADR 0048 fail-closed). Check that the seed directory is reachable, or name "
                    "the archive in [dr].seed_archive",
                    actor,
                    now,
                    requested=archive,
                )
        if resolved is None:
            await self._record_aborted(
                "seed", _REQUEST_ARCHIVE_REFUSED, actor, now, requested=archive
            )
        return str(resolved)

    async def _verify_seed(self, archive: str, actor: str, now: float) -> VerifyResult:
        """Restore-verify the #60 cold-seed archive, FAIL-CLOSED. Reuses ADR 0049's owned primitive
        (:func:`run_restore_verify`). A ``KEY_MISMATCH`` (the DR site does not hold the matching DEK), a
        ``FAIL`` (undecryptable / integrity / row-count), or an unreachable KeyProvider endpoint (AC-14,
        bounded by ``takeover_timeout_seconds``) all abort — recording a ``dr_activation_aborted`` row and
        raising :class:`DrActivationError`. Only a ``PASS`` proceeds."""
        try:
            verify = await asyncio.wait_for(
                run_restore_verify(archive, store_settings=self._store_settings),
                timeout=self._settings.takeover_timeout_seconds,
            )
        except TimeoutError:
            # AC-14: a configured KeyProvider endpoint (KMS/Vault/HSM) reachable only from the PRIMARY site
            # hangs the key resolution; bound it and fail closed — no hang, no silent retry-forever, no
            # plaintext fallback. Distinct from the in-archive decrypt failure (KEY_MISMATCH/FAIL).
            await self._record_aborted(
                "key",
                "KeyProvider unreachable at the DR site (the cold-seed key could not be resolved within "
                f"{self._settings.takeover_timeout_seconds:g}s) — refusing to activate (ADR 0048 AC-14, "
                "fail-closed; provision a DR-reachable/escrowed key)",
                actor,
                now,
            )
        except Exception as exc:  # an unexpected restore-verify error is itself a fail-closed abort
            await self._record_aborted(
                "seed", f"cold-seed restore-verify errored: {safe_exc(exc)}", actor, now
            )
        if verify.status == "KEY_MISMATCH":
            await self._record_aborted(
                "key",
                "the DR site does not hold the DEK the cold-seed archive is encrypted under "
                f"(KEY_MISMATCH: {verify.reason or 'key fingerprint differs'}) — env/external KeyProvider "
                "required at the DR site (DPAPI is machine-bound); refusing to activate (ADR 0048 AC-9)",
                actor,
                now,
            )
        if not verify.ok:
            await self._record_aborted(
                "seed",
                f"cold-seed restore-verify {verify.status}: {verify.reason or 'archive did not verify'} "
                "— refusing to activate against an unverified store (ADR 0048 fail-closed, AC-9)",
                actor,
                now,
            )
        return verify

    async def _verify_seeded_store(self, verify: VerifyResult, actor: str, now: float) -> None:
        """COLD-SEED LOAD GATE — refuse to promote onto a DR store the seed archive was never loaded into.

        Activation *verifies* the ``.mfbak`` seed (step 1) and never loads it: the restore is a separate,
        deliberate step (``messagefoundry restore <archive> --to <store path>``) the operator runs before
        the engine opens the store. A DR box that skipped it opens an EMPTY store — SQLite creates the
        file on open, so an **absent** store and an **empty** one are the same thing by the time
        activation runs — and every earlier check still passes, because they all examine the archive.

        The refusal is one condition with two wordings: the DR store holds **fewer messages than the
        verified seed declares**, zero included. Fail-closed, recorded as ``dr_activation_aborted``.

        Two limits, stated rather than hidden. A seed that declares zero messages cannot be told apart
        from a restore that never happened — both leave the DR store at zero — so that pair is refused
        too, and the error says which of the two readings it could not separate rather than asserting
        the restore was skipped. That is the conservative side of a gate whose whole job is to stop a
        promotion onto a store with nothing in it. And a store restored from a *different* primary of
        the same size passes: the count is a load check, not a provenance check. Exact provenance is
        the ``[dr].restore_token`` vintage floor's job (BACKLOG #223) and extending it to SQLite is
        unfiled work, not something this gate claims.

        **Not** ``Store.has_prior_backup_history()``, which the server-DB gate uses and which looks like
        the obvious answer here: the ``dr_backup`` audit row is written AFTER the snapshot it describes
        (:meth:`BackupRunner._record_success`), so a store restored from a first-ever archive carries
        zero of them and that probe would refuse a perfectly good restore.

        The cost is one ``COUNT(*)`` over the restored ``messages`` table, inside the activation lock and
        outside ``takeover_timeout_seconds``. That is a full scan of a multi-GB restored store on the
        takeover path, paid deliberately: the alternative is promoting onto an unseeded one.

        **No-op on a server-DB store**: there the cold seed is config-only and the live DB is DBA-restored,
        which :meth:`_verify_live_server_seed` already gates (BACKLOG #102).

        **An archive that declares no store row counts is a REFUSAL here, not a no-op.** It used to
        return early, which handed a SQLite box the one gap this gate exists to close: a config-only
        archive verifies ``PASS`` with empty ``row_counts``, :meth:`_verify_live_server_seed` returns
        early because the backend is not a server DB, and both gates then passed an unseeded store
        through — so a deploying site would record a ``dr_seed`` marker and a ``dr.activate`` row
        against a store nothing was ever restored into, which is exactly the silent success ADR 0048's
        amendment, ``docs/CONFIGURATION.md`` and ``docs/EARLY-ADOPTER-GUIDE.md`` state is refused on
        a SQLite store. It cannot be a false refusal: :func:`~messagefoundry.pipeline.dr_backup.
        run_restore` refuses a config-only archive outright, so an archive carrying no store is one no
        SQLite box could have been seeded from in the first place. And a FULL archive always declares
        counts, because :func:`~messagefoundry.pipeline.dr_backup._count_tables` reports every table in
        the snapshot's own schema — a real store has dozens — so empty counts on a ``PASS`` mean
        config-only and nothing else."""
        if self._is_server_db():
            return
        if not verify.row_counts:
            await self._record_aborted(
                "seed",
                "the cold-seed archive verified but declares NO store row counts — a config-only "
                "archive (a --config-only backup, or a server-DB store's DBA-delegated one) carries "
                "no store.db, so nothing could have been restored from it into this box's store. "
                "Seed this box from a full archive (messagefoundry restore <archive> --to <store "
                "path>), then activate. Refusing to promote against a seed that carries no store "
                "(ADR 0048 fail-closed)",
                actor,
                now,
            )
        seeded = int(verify.row_counts.get("messages", 0))
        try:
            present = await self._store.count_messages(allowed_channels=None)
        except Exception as exc:  # a store that cannot be counted cannot be shown to hold the seed
            await self._record_aborted(
                "state",
                f"could not read the DR store's message count to confirm the cold seed was restored "
                f"into it: {safe_exc(exc)}",
                actor,
                now,
            )
        if present == 0 and seeded == 0:
            # Both readings sit on the same number, so name both rather than assert the one that is
            # usually right: a seed taken from an empty primary restores to an empty store, and so
            # does a restore that never ran. The gate cannot separate them and says so.
            await self._record_aborted(
                "seed",
                "the DR store holds 0 messages and the verified cold seed declares 0 as well, so the "
                "restore cannot be told apart from one that never ran. Refusing to promote onto an "
                "empty store (ADR 0048 fail-closed). If this is an empty-primary drill, seed the box "
                "from an archive that carries messages",
                actor,
                now,
            )
        if present == 0:
            await self._record_aborted(
                "seed",
                "the cold-seed archive VERIFIED but was never restored into this box's store: the DR "
                f"store holds 0 messages while the seed carries {seeded}. Restore it first "
                "(messagefoundry restore <archive> --to <store path>), then activate. Refusing to "
                "promote onto an empty store (ADR 0048 fail-closed)",
                actor,
                now,
            )
        if present < seeded:
            await self._record_aborted(
                "seed",
                f"the DR store holds {present} messages but the verified cold seed carries {seeded} — "
                "the restore is partial or this store came from a different archive. Refusing to promote "
                "onto a store that does not carry the seed (ADR 0048 fail-closed)",
                actor,
                now,
            )

    def _is_server_db(self) -> bool:
        """Whether the store is a DBA-delegated server DB (BACKLOG #52). The two seed gates below and
        above split on it in OPPOSITE directions, so it lives in one place: adding a backend, or moving
        one across the DBA-delegated line, must not land it in both the gated and the ungated bucket."""
        return self._store.backend in (StoreBackend.POSTGRES, StoreBackend.SQLSERVER)

    async def _verify_live_server_seed(
        self, dba_attests_restored: bool, actor: str, now: float
    ) -> None:
        """SERVER-DB live seed gate (BACKLOG #102) — the O3 data-loss fix. On a Postgres/SQL Server store
        the #60 backup is ``config_only`` (``snapshot_to`` is DBA-delegated), so :func:`run_restore_verify`
        returns ``PASS`` on the manifest WITHOUT restoring or inspecting the DBA-managed live ``mefor`` DB.
        That would let activation promote priority feeds against a FRESH/UNRESTORED server store —
        non-empty only because ``provision-admin``, engine startup and operator sign-in wrote to
        ``audit_log``. This gate closes that. It is a **no-op on SQLite** (the archive already
        carried + verified the whole store — the byte-identical path).

        Two independent conditions, either failing aborts closed (records ``dr_activation_aborted`` +
        raises :class:`DrActivationError` via :meth:`_record_aborted`):

        1. an **explicit DBA attestation** (``dba_attests_restored`` — the engine cannot itself restore a
           DBA-managed DB, so activation must be a deliberate act); absent → abort; and
        2. a **live restore-provenance probe** (:meth:`Store.has_prior_backup_history`): the restored DB
           must carry ≥1 ``dr_backup`` audit row — present on any DB restored from an operating primary
           (the primary writes one on every leader-gated backup, the run that produced the seed) and ABSENT
           on a fresh DR-box install (a passive standby is never the leader). An unreachable DB / missing
           ``audit_log`` raises → abort; a fresh/unrestored DB (no ``dr_backup`` row) → abort **even when
           attested** (defense in depth: a mistaken attestation must still fail closed). The probe runs off
           the event loop via the async store API (a pooled read-only round-trip; no mutation).

        RESIDUAL (BACKLOG #102 → #223, ADR 0102): the (a)+(b) checks prove prior backup history, NOT the
        vintage or completeness of a DBA-managed restore. A stale-but-real restore, or a partial restore
        that carried ``audit_log`` but not the message tables, still passes conditions (a)+(b) — the engine
        has no artifact to verify a DBA-managed DB against (the config-only ``.mfbak`` is a decoupled
        backup). #223 formally ACCEPTS that residual (ASVS-style risk acceptance) AND adds an OPT-IN third
        condition:

        3. an OPTIONAL **restore-token cross-check** (:meth:`_verify_restore_token`), active ONLY when
           ``[dr].restore_token`` is set. It gives a VINTAGE FLOOR a bare boolean attestation cannot — but
           it is still an attestation (does not prove message-table completeness), an explicitly WEAKER
           posture than SQLite (which snapshot-verifies the whole store), not a match for it. Unset (the
           default) → this method is byte-identical to the #102 gate."""
        if not self._is_server_db():
            # SQLite: the cold-seed archive verified the whole store.db (integrity_check + row counts).
            # Nothing to add — leave the path byte-identical (BACKLOG #102 is a server-DB-only gap).
            return
        # (a) Explicit, per-activation DBA attestation. A server-DB ``mefor`` DB is restored OUT of band by
        # a DBA; the engine has no way to prove it happened, so it refuses to promote onto it without the
        # operator's deliberate attestation. Absent → fail closed (secure-by-default).
        if not dba_attests_restored:
            await self._record_aborted(
                "seed",
                "server-DB store (postgres/sqlserver): the DR 'mefor' database is DBA-restored and the "
                "config-only cold-seed archive cannot verify it — refusing to activate without an explicit "
                "DBA attestation that the database has been restored (pass dba_attests_restored=true on "
                "POST /dr/activate); ADR 0048 fail-closed, BACKLOG #102",
                actor,
                now,
            )
        # (b) Live restore-provenance probe (defense in depth) — even WITH the attestation, the restored DB
        # must carry prior backup history (≥1 dr_backup row), which a fresh/unrestored install lacks.
        try:
            restored = await self._store.has_prior_backup_history()
        except Exception as exc:  # unreachable / absent / no audit_log table on the restored DB
            await self._record_aborted(
                "seed",
                "server-DB live seed probe failed (the restored 'mefor' database is unreachable or has no "
                f"audit_log): {safe_exc(exc)} — refusing to activate (ADR 0048 fail-closed, BACKLOG #102)",
                actor,
                now,
            )
        if not restored:
            await self._record_aborted(
                "seed",
                "server-DB live seed probe: the restored 'mefor' database carries NO prior backup history "
                "(no dr_backup audit row) — it looks freshly bootstrapped, not restored from the primary; "
                "a DBA attestation was given but the database was not actually restored. Refusing to "
                "activate against a fresh/unrestored store (ADR 0048 fail-closed defense-in-depth, "
                "BACKLOG #102)",
                actor,
                now,
            )
        # (c) OPTIONAL restore-token vintage-floor cross-check (BACKLOG #223, ADR 0102). Runs ONLY when the
        # operator opted in via [dr].restore_token; unset → this is a no-op and the gate is byte-identical
        # to #102. A stale/wrong native restore's latest dr_backup anchor differs from the DBA-recorded
        # expected one, so this refuses it closed — a vintage floor a bare boolean attestation cannot give.
        if self._settings.restore_token:
            await self._verify_restore_token(actor, now)

    async def _verify_restore_token(self, actor: str, now: float) -> None:
        """OPTIONAL server-DB restore-token cross-check (BACKLOG #223, ADR 0102 — option b). Active only
        when ``[dr].restore_token`` is set. The DBA/operator places a small JSON token on the DR box —
        ``{"expected_backup_archive": "<archive name>"}`` — recording the EXPECTED source-backup anchor of
        the native restore: the ``archive`` filename of the most-recent engine ``dr_backup`` the restored
        ``mefor`` DB should carry, sourced OUT-of-band from the PRIMARY's backup record (NOT read back from
        the restored DB, which would be self-fulfilling). This gate reads that expected anchor and the
        restored DB's OWN latest *successful* ``dr_backup`` archive (via :meth:`_latest_backup_archive`) and
        requires them to MATCH: a stale-but-real restore carries an OLDER latest anchor and is refused; a
        wrong DB carries a DIFFERENT anchor and is refused — closing part of the #102 vintage residual (it
        does NOT prove message-table completeness; that is deferred option (a)). Every failure aborts closed
        (records ``dr_activation_aborted`` + raises :class:`DrActivationError`, kind ``seed``). The token is
        read OFF the event loop; it carries only a PHI-free archive filename."""
        token_path = self._settings.restore_token
        try:
            text = await asyncio.to_thread(Path(token_path).read_text, encoding="utf-8")
        except OSError as exc:
            await self._record_aborted(
                "seed",
                "server-DB restore-token cross-check: the configured [dr].restore_token file could not be "
                f"read ({safe_exc(exc)}) — the DBA must place the recorded source-backup anchor on the DR "
                "box before activation (BACKLOG #223, ADR 0102 fail-closed)",
                actor,
                now,
            )
        expected = _parse_restore_token(text)
        if expected is None:
            await self._record_aborted(
                "seed",
                "server-DB restore-token cross-check: the [dr].restore_token file is not a JSON object "
                "carrying a non-empty 'expected_backup_archive' string — refusing to activate (BACKLOG "
                "#223, ADR 0102 fail-closed)",
                actor,
                now,
            )
        restored_anchor = await self._latest_backup_archive()
        if restored_anchor is None:
            await self._record_aborted(
                "seed",
                "server-DB restore-token cross-check: the restored 'mefor' database carries no SUCCESSFUL "
                "dr_backup audit row to anchor a vintage against — refusing to activate (BACKLOG #223, "
                "ADR 0102 fail-closed)",
                actor,
                now,
            )
        if restored_anchor != expected:
            await self._record_aborted(
                "seed",
                "server-DB restore-token cross-check: the restored database's latest dr_backup anchor does "
                "NOT match the DBA-recorded expected source backup — the native restore is a different "
                "(likely STALE) vintage than intended. Refusing to activate (BACKLOG #223, ADR 0102 "
                "fail-closed vintage floor)",
                actor,
                now,
            )
        log.warning(
            "DR restore-token cross-check PASSED: the restored vintage matches the DBA-recorded source "
            "backup anchor (BACKLOG #223)"
        )

    async def _latest_backup_archive(self) -> str | None:
        """The ``archive`` filename of the restored store's most-recent SUCCESSFUL ``dr_backup`` audit row,
        or ``None`` if none is found. Scans the recent ``dr_backup`` rows (most-recent-first) and returns
        the first whose PHI-free ``detail`` carries an ``archive`` field — a FAILURE row's detail is
        ``{"outcome": "error", ...}`` with no ``archive``, so it is skipped. Read-only (a single bounded,
        indexed ``list_audit`` query); the archive filename is PHI-free (instance + UTC only)."""
        rows = await self._store.list_audit(action="dr_backup", limit=50)
        for row in rows:
            if "detail" not in row.keys():  # noqa: SIM118
                continue
            raw = row["detail"]
            if not isinstance(raw, str):
                continue
            try:
                parsed = json.loads(raw)
            except ValueError:
                continue
            if isinstance(parsed, dict):
                archive = parsed.get("archive")
                if isinstance(archive, str) and archive:
                    return archive
        return None

    async def _record_seed_marker(self, archive: str, verify: VerifyResult, now: float) -> str:
        """Open a NEW audit-chain segment on the cold-seeded box: record a ``dr_seed`` marker whose
        genesis is the source-backup snapshot SHA-256 + the config/DEK fingerprints + the **restored
        chain's tip hash** (read via :meth:`Store.audit_anchor`). Each side then stays independently
        verifiable and the fork is explicit/attributable, rather than blindly extending the restored chain
        (ADR 0049/0041 audit-chain-fork handling). Returns the marker row's own hash digest (PHI-free)."""
        # Before the anchor read, so the hash of the config dir does not widen the window in which
        # another audit row could land between the anchor and this marker.
        provider = self._config_fingerprint_provider
        config_fp = await provider() if provider is not None else None
        restored_seq, restored_tip = await self._store.audit_anchor()
        cipher = self._store.cipher_info()
        marker = {
            "kind": "dr_seed",
            "archive": _basename(archive),
            "verify": verify.status,
            # The source-backup fingerprints carried in the seed archive's manifest are summarized by the
            # verify result's row counts; record the restored chain's tip so the segment fork is anchored.
            # The restored chain's newest sequence number: the coordinate its row MACs cover and
            # an anchor names, so the marker and an out-of-band anchor can be compared directly.
            "restored_audit_seq": restored_seq,
            "restored_audit_tip": restored_tip,
            "config_fingerprint": config_fp,
            "dek_fingerprint": cipher.active_key_id,  # one-way fingerprint, NEVER key bytes
        }
        detail = json.dumps(marker, sort_keys=True)
        await self._store.record_audit(_ACTION_SEED, actor="system", detail=detail, now=now)
        # The marker's own row hash is the new segment's genesis anchor; read it back for the result.
        _count, head = await self._store.audit_anchor()
        return head

    async def _run_vip_hook(self, command: str, *, phase: str, actor: str, now: float) -> bool:
        """Run the optional VIP takeover/release hook OFF the event loop (a subprocess). Exit 0 = success
        ("VIP acquired"/"VIP released"); any non-zero or a timeout is a failure. On the **takeover** phase
        a failure ABORTS activation (acquire-VIP-or-abort) + records ``dr_activation_aborted``; on the
        **release** phase a failure is logged but does not block the hand-back (the passive LB still moves
        the VIP when intake unbinds — the hook is belt-and-braces). Returns whether the hook ran. ``""`` =
        no hook (rely on the passive ADR-0047 LB)."""
        if not command:
            return False
        try:
            # Only a takeover hook is killed when it overruns: an aborted activation must not be
            # left taking the address. A release hook is left to finish late, as before, since
            # killing it partway could strand the address on this box (vault BACKLOG #2622).
            ok = await asyncio.wait_for(
                _run_command(command, stop_kills=phase == "takeover"),
                timeout=self._settings.takeover_timeout_seconds,
            )
        except TimeoutError:
            ok = False
            reason = (
                f"VIP {phase} hook timed out after {self._settings.takeover_timeout_seconds:g}s"
            )
        except Exception as exc:
            ok = False
            reason = f"VIP {phase} hook errored: {safe_exc(exc)}"
        else:
            reason = "" if ok else f"VIP {phase} hook exited non-zero"
        if not ok:
            if phase == "takeover":
                await self._record_aborted(
                    "vip",
                    f"{reason} — VIP not acquired; aborting activation, binding no priority listener, "
                    "staying passive (acquire-VIP-or-abort, ADR 0048)",
                    actor,
                    now,
                )
            else:
                # Release-hook failure is non-fatal (the passive LB returns the VIP on unbind); log loudly.
                log.warning(
                    "DR release: %s — continuing hand-back (passive LB moves the VIP)", reason
                )
        return True

    async def _record_aborted(
        self, kind: str, message: str, actor: str, now: float, *, requested: str | None = None
    ) -> NoReturn:
        """Record a ``dr_activation_aborted`` audit row (PHI-free) + raise :class:`DrActivationError`. The
        single fail path for every refused activation, so an aborted promotion always leaves an audit
        trail and the caller gets the failing phase. Never returns (always raises). ``requested`` is
        a refused request path: it goes in the audit row and never in the raised message."""
        await self._write_aborted_row(kind, message, actor, now, requested=requested)
        raise DrActivationError(kind, message)

    async def _write_aborted_row(
        self, kind: str, message: str, actor: str, now: float, *, requested: str | None = None
    ) -> None:
        """The ``dr_activation_aborted`` row and its log line, without the raise. Best-effort:
        recording the abort must never mask the abort itself."""
        detail = {"kind": kind, "reason": message}
        if requested is not None:
            detail["requested"] = requested
        try:
            await self._store.record_audit(
                _ACTION_ABORTED,
                actor=actor,
                detail=json.dumps(detail, sort_keys=True),
                now=now,
            )
        except Exception:
            # Recording the abort must itself never mask the abort — log and proceed to raise.
            log.warning("DR: could not record the dr_activation_aborted audit row", exc_info=True)
        log.warning("DR activation ABORTED (%s): %s", kind, message)

    def _alert_dr(self, event: str) -> None:
        """Emit a #145 DR transition alert (``dr_activated`` on promotion / ``dr_released`` on fail-back)
        on the injected sink. Never-raise: a notification failure must never undo a completed
        activate/release. The emit is synchronous + non-blocking (the notifier only enqueues); the payload
        carries only the box label + role (no PHI)."""
        try:
            if event == "dr_activated":
                self._alert_sink.dr_activated(self._node, role="dr_standby")
            else:
                self._alert_sink.dr_released(self._node, role="primary")
        except Exception:  # pragma: no cover - defensive; a sink must never break DR
            log.warning("DR: %s alert failed", event, exc_info=True)


async def _run_command(command: str, *, stop_kills: bool = True) -> bool:
    """Run an operator-supplied shell command OFF the event loop and return whether it exited 0. Uses the
    asyncio subprocess API (never blocks the loop). The command is operator-configured (``[dr]``), not
    request-derived, so it is run via the shell exactly as the operator wrote it (parity with the way the
    backup destination / other operator-configured paths are trusted).

    Its environment is :func:`messagefoundry.childenv.hook_environment`: the operator's ordinary
    variables, without the engine's own (vault BACKLOG #2587).

    **Stopping it stops the whole hook, when** ``stop_kills`` (vault BACKLOG #2622). The caller
    bounds this with ``wait_for``, which stops it by cancelling it. Cancelling only the wait would
    leave the shell and whatever it started running, so an activation recorded as aborted could
    still be taking the address. So the shell starts as the root of a tree
    :mod:`messagefoundry.proctree` can kill, and a cancel kills that tree before it propagates.
    With ``stop_kills=False`` the hook starts as it did before, in no tree of its own, and a
    cancel leaves it running. On Windows that also keeps it out of a kill-on-close job, which
    would end it when the engine exits. Anything outside this code that stops the engine's
    processes, such as a service wrapper's tree kill or a signal to the engine's process group,
    can still end it. A hook that finishes on its own is left alone either way, including
    anything it left running."""
    spawn = asyncio.ensure_future(
        asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
            env=hook_environment(),
            creationflags=proctree.ADOPT_CREATIONFLAGS if stop_kills else 0,
            start_new_session=proctree.ADOPT_NEW_SESSION and stop_kills,
        )
    )
    try:
        # Shielded so a stop that lands mid-start cannot lose the process: the callback kills it.
        # On Windows a hook this may kill is still suspended then, so it has done nothing yet.
        proc = await asyncio.shield(spawn)
    except (asyncio.CancelledError, GeneratorExit):
        spawn.add_done_callback(_kill_late_start if stop_kills else _leave_late_start)
        raise
    job: int | None = None
    try:
        if stop_kills:
            job = proctree.resume_into_job(proc.pid, who="DR takeover hook")
        await proc.wait()
    except GeneratorExit:
        if stop_kills:
            _kill_hook(proc, job)  # a closing coroutine may not await, so no reap
        raise
    except BaseException:
        if stop_kills:
            _kill_hook(proc, job)
            await _reap_hook(proc)
        raise
    if job is not None:
        proctree.release_job(job)
    return proc.returncode == 0


#: How long a killed hook gets to be reaped before the abort carries on without it. This adds to
#: ``[dr].takeover_timeout_seconds`` in the worst case. docs/CONFIGURATION.md quotes it, and
#: tests/test_dr_activation.py pins that quote.
_HOOK_REAP_SECONDS = 5.0

#: Reaps started from a done-callback, held so the loop does not drop them mid-wait.
_LATE_REAPS: set[asyncio.Task[None]] = set()


def _kill_hook(proc: asyncio.subprocess.Process, job: int | None) -> None:
    """Kill the hook's shell and what it started.

    Windows ends the job. POSIX signals the group the shell was started to lead. That group outlives
    the shell, so it is signalled even when the shell has already exited: its children may not have.
    POSIX does not reuse a group's id while the group has members, so the signal cannot reach an
    unrelated group then. Once the group is empty its id can be reused, which is the same narrow
    risk any kill by process id carries. The single-process kill is the fallback for a job that
    could not be set up, and it never raises: the stop that called it must carry on."""
    if job is not None:
        proctree.terminate_job(job)
        return
    if proctree.kill_process_group(proc.pid, started_as_leader=proctree.ADOPT_NEW_SESSION):
        return
    if proc.returncode is None:
        try:
            proc.kill()
        except ProcessLookupError:
            pass  # it exited on its own in the meantime
        except OSError as exc:
            log.warning("DR hook (pid %d) could not be killed: %s", proc.pid, safe_exc(exc))


async def _reap_hook(proc: asyncio.subprocess.Process) -> None:
    """Wait for the killed shell to exit, bounded, and say so when it has not."""
    try:
        await asyncio.wait_for(proc.wait(), _HOOK_REAP_SECONDS)
    except TimeoutError:
        log.warning(
            "DR hook (pid %d) was killed but had not exited %gs later; it may still be running",
            proc.pid,
            _HOOK_REAP_SECONDS,
        )


def _kill_late_start(spawn: asyncio.Future[asyncio.subprocess.Process]) -> None:
    """Kill a hook whose start finished after its caller was stopped, then reap it. On Windows it
    is still suspended, so it has started nothing and killing the one process is enough."""
    if spawn.cancelled() or spawn.exception() is not None:
        return
    proc = spawn.result()
    _kill_hook(proc, None)
    reap = spawn.get_loop().create_task(_reap_hook(proc))
    _LATE_REAPS.add(reap)
    reap.add_done_callback(_LATE_REAPS.discard)


def _leave_late_start(spawn: asyncio.Future[asyncio.subprocess.Process]) -> None:
    """Let a release hook whose start finished after its caller was stopped run on. A failed
    start is read here, so asyncio does not log it as an exception nobody retrieved."""
    if not spawn.cancelled():
        spawn.exception()


def _confined_archive(archive: str, seed_dir: str) -> Path | None:
    """``archive`` resolved, if it lies under ``seed_dir``; ``None`` if not. Resolves ``seed_dir``
    first, which is operator configuration, so run this off the event loop. ``archive`` may spell
    the directory as configured or as it resolves."""
    root = Path(seed_dir).resolve()
    return confine(
        archive,
        lexical=lexical_roots([seed_dir, root]),
        resolved=[root],
        what="DR request archive",
    )


def _count(value: object) -> int | None:
    """``value`` if it is a count (an ``int`` that is not a ``bool``), else ``None``."""
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _flag(value: object) -> bool | None:
    """``value`` if it is a ``bool``, else ``None``."""
    return value if isinstance(value, bool) else None


def _release_detail(hook_ran: bool, drain: Mapping[str, object] | None) -> dict[str, object]:
    """The ``dr.release`` row's detail, from the engine callback's ``drain`` fields. ``drained`` is
    the drain's real result, never a constant (vault BACKLOG #2752, finding D-V1). The engine
    reports it, because only the engine knows which rows are held on parked outbounds and so
    cannot drain (vault BACKLOG #3067). A callback that reports a depth and no verdict reads as
    drained when that depth is ``0``; one that reports neither leaves ``drained`` ``None``."""
    fields = drain or {}
    depth = _count(fields.get("depth_left"))
    drained = _flag(fields.get("drained"))
    if drained is None and depth is not None:
        drained = depth == 0
    detail: dict[str, object] = {"vip_hook_ran": hook_ran, "drained": drained, "depth_left": depth}
    held = _count(fields.get("held_on_parked_outbounds"))
    if held is not None:
        detail["held_on_parked_outbounds"] = held
    return detail


def _basename(path: str) -> str:
    """The archive filename (not the full path) — what the audit detail / result carry (no directory
    layout disclosure, and it is the operator-meaningful identifier)."""
    from pathlib import PurePath

    return PurePath(path).name if path else ""


def _parse_restore_token(text: str) -> str | None:
    """Parse a restore-token file body → the expected source-backup ``archive`` name (BACKLOG #223, ADR
    0102), or ``None`` if the body is not a JSON object carrying a non-empty ``expected_backup_archive``
    string. PHI-free (an archive filename only). A ``None`` return is treated by the caller as a
    fail-closed abort (an opted-in but unsatisfiable check never silently passes)."""
    try:
        doc = json.loads(text)
    except ValueError:
        return None
    if not isinstance(doc, dict):
        return None
    expected = doc.get("expected_backup_archive")
    if isinstance(expected, str) and expected.strip():
        return expected.strip()
    return None
