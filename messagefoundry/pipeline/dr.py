# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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
   same fail-closed abort (AC-14), distinct from the in-archive decrypt failure (AC-9).
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
   the injected ``activate_profile`` callback, and a ``dr.activate`` audit row records the promotion.

:meth:`release` is **drain-then-hand-back**: release the VIP (the optional ``release_hook`` / let the
passive LB return it to the recovered primary), wait for convergence, unbind intake while the workers
drain the staged queue to completion (delivered/dead-lettered) — preserving at-least-once + idempotency
**within the DR store** — then record ``dr.release``. **Cross-store** reconciliation with the recovered
primary is operator-verified per the runbook (the engine gives NO cross-store loss/duplicate guarantee).

This module is engine-side and dependency-light (stdlib + the store/settings/dr_backup seams), so it
never pulls the API or console into the engine. The VIP hook runs OFF the event loop (a subprocess) so
it never blocks asyncio; **PHI is never logged** (only counts / paths / one-way fingerprints).
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import NoReturn

from messagefoundry.config.settings import DrSettings
from messagefoundry.pipeline.alerts import AlertSink, LoggingAlertSink
from messagefoundry.pipeline.dr_backup import VerifyResult, run_restore_verify
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


class DrActivationError(RuntimeError):
    """Activation (or release) was refused. Carries a ``kind`` (``seed``/``key``/``vip``/``profile``/
    ``state``) so the caller (the API endpoint) can map it to an HTTP error and the operator sees the
    failing phase. The message is ``safe_exc``-scrubbed (PHI-free)."""

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


class DrCoordinator:
    """Manual, audited DR promotion/fail-back (ADR 0048). Construct with the open store + ``[dr]``
    settings + the store settings (the KeyProvider seam for restore-verify) + two engine callbacks that
    flip the DR run-profile (``activate_profile`` reloads the graph with the run-profile ON;
    ``deactivate_profile`` unbinds intake + drains, then turns it OFF). Single-writer: the API serializes
    activate/release behind ``[approvals]``-style RBAC; this object additionally guards against a
    concurrent activate/release with its own lock."""

    def __init__(
        self,
        store: Store,
        settings: DrSettings,
        *,
        store_settings: object,
        activate_profile: Callable[[], Awaitable[None]],
        deactivate_profile: Callable[[], Awaitable[None]],
        config_fingerprint: str | None = None,
        alert_sink: AlertSink | None = None,
        clock: Callable[[], float] = time.time,
        owned_lanes: Callable[[], OwnedLanes | None] | None = None,
    ) -> None:
        self._store = store
        self._settings = settings
        # The store settings carry the KeyProvider seam (ADR 0019) — the DEK the cold-seed archive is
        # encrypted under. Typed loosely to avoid importing StoreSettings here; run_restore_verify takes it.
        self._store_settings = store_settings
        self._activate_profile = activate_profile
        self._deactivate_profile = deactivate_profile
        self._config_fingerprint = config_fingerprint
        self._alert_sink: AlertSink = alert_sink or LoggingAlertSink()
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

    async def activate(self, *, archive: str | None = None, actor: str = "system") -> DrResult:
        """Promote this DR box (ADR 0048 fixed ordering: cold-seed restore-verify → new audit segment →
        acquire-VIP-or-abort → serve under the DR run-profile). MANUAL only — there is no auto-probe in
        this slice; the caller (``POST /dr/activate``) is RBAC-gated by ``dr:operate`` and supplies the
        operator ``actor`` for the audit rows.

        ``archive`` overrides ``[dr].seed_archive`` (the runbook may pass the chosen #60 backup in the
        request body). Raises :class:`DrActivationError` and records a ``dr_activation_aborted`` audit row
        on any abort; never leaves the VIP held against a store that will not open (the restore-verify
        fail-closes BEFORE the VIP step)."""
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
                return DrResult(
                    action="activate",
                    active=True,
                    threshold=self._settings.priority_threshold.value,
                )
            seed = archive or self._settings.seed_archive
            now = self._clock()

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

            # (2) Recover the cold-restored store (every stage, AC-15) + open a NEW audit-chain segment
            # (the seed-marker genesis; do NOT blindly extend the restored chain — ADR 0049/0041).
            # Ownership-scoped when sharded (ADR 0073) — see _owned_lanes in __init__.
            try:
                await self._store.reset_stale_inflight(
                    owned=self._owned_lanes() if self._owned_lanes is not None else None
                )
            except (
                Exception
            ) as exc:  # a store that can't recover its own residue can't safely serve
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
            hook_ran = await self._run_vip_hook(
                self._settings.takeover_hook, phase="takeover", actor=actor, now=now
            )

            # (4) Serve under the DR run-profile: bind only the connections at/above the threshold (the
            # rest report status:"filtered"). The engine reloads the graph with the run-profile ON.
            try:
                self._active = True
                await self._activate_profile()
            except Exception as exc:
                self._active = False
                await self._record_aborted(
                    "profile",
                    f"DR run-profile activation failed (the engine could not bind the priority feeds): "
                    f"{safe_exc(exc)}",
                    actor,
                    now,
                )

            await self._store.record_audit(
                _ACTION_ACTIVATE,
                actor=actor,
                detail=json.dumps(
                    {
                        "archive": _basename(seed),
                        "verify": verify.status,
                        "threshold": self._settings.priority_threshold.value,
                        "seed_segment": seed_segment,
                        "vip_hook_ran": hook_ran,
                    },
                    sort_keys=True,
                ),
                now=now,
            )
            log.warning(
                "DR ACTIVATED by %s: serving feeds at priority >= %s; cold seed %s verified %s "
                "(new audit-chain segment opened)",
                actor,
                self._settings.priority_threshold.value,
                _basename(seed),
                verify.status,
            )
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
                return DrResult(
                    action="release",
                    active=False,
                    threshold=self._settings.priority_threshold.value,
                )
            # Release the VIP FIRST (so partners reconnect to the primary), then unbind intake + drain.
            # Order matters: the VIP must be off the DR box before — or as — intake stops, so no message
            # is dual-accepted while the VIP moves.
            hook_ran = await self._run_vip_hook(
                self._settings.release_hook, phase="release", actor=actor, now=now
            )
            try:
                await (
                    self._deactivate_profile()
                )  # unbind listeners, drain the staged queue to completion
            except Exception as exc:
                # A failed drain leaves the box active (still draining) — report it loudly, do NOT claim a
                # clean hand-back (a half-drained release would risk cross-store divergence the runbook
                # can't account for).
                raise DrActivationError(
                    "state",
                    f"DR release drain failed; the box stays active (retry release): {safe_exc(exc)}",
                ) from exc
            self._active = False
            await self._store.record_audit(
                _ACTION_RELEASE,
                actor=actor,
                detail=json.dumps({"vip_hook_ran": hook_ran, "drained": True}, sort_keys=True),
                now=now,
            )
            log.warning(
                "DR RELEASED by %s: VIP handed back, intake unbound, staged queue drained — the "
                "recovered primary resumes (cross-store reconciliation is operator-verified per the runbook)",
                actor,
            )
            return DrResult(
                action="release",
                active=False,
                threshold=self._settings.priority_threshold.value,
                vip_hook_ran=hook_ran,
            )

    # --- internals -----------------------------------------------------------

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
        except asyncio.TimeoutError:
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

    async def _record_seed_marker(self, archive: str, verify: VerifyResult, now: float) -> str:
        """Open a NEW audit-chain segment on the cold-seeded box: record a ``dr_seed`` marker whose
        genesis is the source-backup snapshot SHA-256 + the config/DEK fingerprints + the **restored
        chain's tip hash** (read via :meth:`Store.audit_anchor`). Each side then stays independently
        verifiable and the fork is explicit/attributable, rather than blindly extending the restored chain
        (ADR 0049/0041 audit-chain-fork handling). Returns the marker row's own hash digest (PHI-free)."""
        restored_count, restored_tip = await self._store.audit_anchor()
        cipher = self._store.cipher_info()
        marker = {
            "kind": "dr_seed",
            "archive": _basename(archive),
            "verify": verify.status,
            # The source-backup fingerprints carried in the seed archive's manifest are summarized by the
            # verify result's row counts; record the restored chain's tip so the segment fork is anchored.
            "restored_audit_count": restored_count,
            "restored_audit_tip": restored_tip,
            "config_fingerprint": self._config_fingerprint,
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
            ok = await asyncio.wait_for(
                _run_command(command), timeout=self._settings.takeover_timeout_seconds
            )
        except asyncio.TimeoutError:
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

    async def _record_aborted(self, kind: str, message: str, actor: str, now: float) -> NoReturn:
        """Record a ``dr_activation_aborted`` audit row (PHI-free) + raise :class:`DrActivationError`. The
        single fail path for every refused activation, so an aborted promotion always leaves an audit
        trail and the caller gets the failing phase. Never returns (always raises)."""
        try:
            await self._store.record_audit(
                _ACTION_ABORTED,
                actor=actor,
                detail=json.dumps({"kind": kind, "reason": message}, sort_keys=True),
                now=now,
            )
        except Exception:
            # Recording the abort must itself never mask the abort — log and proceed to raise.
            log.warning("DR: could not record the dr_activation_aborted audit row", exc_info=True)
        log.warning("DR activation ABORTED (%s): %s", kind, message)
        raise DrActivationError(kind, message)


async def _run_command(command: str) -> bool:
    """Run an operator-supplied shell command OFF the event loop and return whether it exited 0. Uses the
    asyncio subprocess API (never blocks the loop). The command is operator-configured (``[dr]``), not
    request-derived, so it is run via the shell exactly as the operator wrote it (parity with the way the
    backup destination / other operator-configured paths are trusted)."""
    proc = await asyncio.create_subprocess_shell(
        command,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    await proc.wait()
    return proc.returncode == 0


def _basename(path: str) -> str:
    """The archive filename (not the full path) — what the audit detail / result carry (no directory
    layout disclosure, and it is the operator-meaningful identifier)."""
    from pathlib import PurePath

    return PurePath(path).name if path else ""
