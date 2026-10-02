# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Apply a replaced CRL file to the running hops that hold the old copy, without a restart (BACKLOG #299).

**The gap this closes.** A hop reads its CRL when it builds its TLS context and keeps that context.
Before this module an operator who replaced a CRL file had to restart the engine before any running
hop saw it: a revocation added to the new file was not enforced, and the old copy went on toward its
``nextUpdate``, past which it refuses every peer. :mod:`messagefoundry.config.loaded_crls` made the
expiry alert say so. This module removes the need for the restart wherever a hop recorded its load.

**How: add the new CRL to the live context.** Python's ``ssl.SSLContext`` can load a CRL but never
unload one, and rebuilding each hop's context would need a seam per hop that most hops do not have.
Adding is enough, because of how OpenSSL picks a CRL. For one issuer it scores each CRL it holds: time
validity, scope (the Issuing Distribution Point), Authority Key Identifier and unhandled critical
extensions all count. Among equal scores it takes the latest ``thisUpdate``. Measured on CPython 3.14 /
OpenSSL 3.5.7: a context holding a clean CRL and then given a newer one that revokes the peer refuses
the peer, in either load order.

**That holds only when the new file supersedes every CRL the context already holds.** For each CRL the
running copy carries, the file must carry the same CRL, or one from the same issuer that scores alike
(:class:`~messagefoundry.pki.CrlBlock` ``selection``), with a later ``thisUpdate`` that is already in
effect and a ``nextUpdate`` no earlier. Then no held CRL can ever be chosen over the file's, and the
context checks exactly what the file says. A file that fails this, such as a rollback to an older CRL,
one that drops an issuer, or one signed under a new key, is refused here, and a restart applies it.
One superseding step is enough for the next by transitivity: each held CRL is superseded by the file
that replaced it, and that file by the next one.

**Every refusal keeps the old copy, and fails closed.** The replacement must first pass the rules a
start applies (:func:`~messagefoundry.config.tls_policy.judge_crl_bytes`): every block parses, has a
``nextUpdate``, is not a delta CRL, and none has expired. Then it must carry no certificate the hop
does not already trust (BACKLOG #1890). A load cannot be undone, so that is proved on a scratch context
BEFORE the live one sees the bytes. The live context then loads a private copy of the judged bytes in
a directory only this account can write, never the operator's file a second time. There is no check
after the live load: a certificate count read then races the lazy loading of a hashed root directory,
and nothing found there could be undone anyway. A refusal is logged at ERROR once per file version and
recorded, so the expiry monitor says why the hop's copy is still old. The old copy keeps its
``crl_expiry`` alert.

**A context's trust store only grows.** Each reload adds the file's CRLs and nothing removes the old
ones, so memory and per-handshake CRL scoring grow with every reload. :data:`MAX_RELOADS` bounds it: a
context that has taken that many reloads for one file refuses the next, and a restart starts it afresh.

**What this does not reach.** At least these. Each needs a restart, or for the first, a reconnect:

* an established TLS connection, or a session resumed from an earlier handshake. A reload changes what
  the NEXT full handshake checks; a long-lived MLLP connection from a newly revoked partner stays up;
* a CRL block inside a CA bundle, which nothing records;
* a hop whose CRL load was not recorded. The Postgres store records none, and needs no reload: it
  builds a fresh context per pool connection, so a new connection reads the file;
* a replacement this module refuses.

**Off the event loop, on purpose.** :class:`CrlReloadRunner` runs each pass in a worker thread. The
live load mutates a context the loop may be handshaking with. OpenSSL takes the trust store's lock both
to add a CRL and to look one up, so a handshake sees the store before or after the add, never torn.

Engine-side and stdlib plus ``cryptography`` (through :mod:`messagefoundry.pki`). It reads CRLs and
public CA certificates, never key material or message content.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime
import logging
import ssl
import tempfile
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from pathlib import Path

from messagefoundry.config.loaded_crls import (
    HeldCrl,
    ReloadRefusal,
    clear_reload_refusal,
    crl_fingerprint,
    held_contexts,
    record_reload_refusal,
    reload_refusal,
    replace_held_copy,
)
from messagefoundry.config.tls_policy import crl_label, judge_crl_bytes
from messagefoundry.pki import CrlBlock

__all__ = [
    "FIX",
    "MAX_RELOADS",
    "RELOAD_INTERVAL_SECONDS",
    "RESTART",
    "WAIT",
    "CrlReloadRunner",
    "ReloadOutcome",
    "reload_replaced_crls",
    "supersede_refusal",
]

log = logging.getLogger(__name__)

#: How often the engine looks for a replaced CRL file. A pass reads each held CRL file once and does
#: nothing more unless a file changed, so a minute is cheap, and it bounds how long a revocation added
#: to the file goes unenforced by a new handshake on a running hop.
RELOAD_INTERVAL_SECONDS = 60.0

#: Reloads one context takes for one file before it refuses and asks for a restart. A daily CRL
#: reaches it in about eight months, an hourly one in about ten days.
MAX_RELOADS = 256

#: The remedies a refusal carries. A refusal names exactly one, chosen where the refusal is made.
RESTART = "Restart the engine to apply the file"
FIX = "Fix the file: the engine would refuse to start on it too"
WAIT = (
    "Wait: the engine applies the file once its CRL takes effect. Do not restart before then, "
    "because a hop that loads a CRL not yet in effect refuses every peer"
)


@dataclass(frozen=True)
class ReloadOutcome:
    """What one pass did for one CRL file that a running context held an older copy of."""

    path: str
    #: Contexts now checking against the file.
    reloaded: int
    #: Why some or all of the stale contexts kept their old copy, or ``None`` when none did.
    refusal: ReloadRefusal | None


def supersede_refusal(
    held: Sequence[CrlBlock], new: Sequence[CrlBlock], *, now: float
) -> tuple[str, bool] | None:
    """Why adding ``new`` to a context holding ``held`` would NOT leave it checking exactly ``new``,
    or ``None`` when it would. The flag is True when the only thing missing is time: the file has a
    superseding CRL that is not in effect yet. The module docstring gives the rule."""
    if not held:
        reason = (
            "the CRLs of the running copy were not recorded, so the engine cannot prove the file "
            "supersedes them"
        )
        return reason, False
    when = datetime.datetime.fromtimestamp(now, tz=datetime.UTC)
    same = {block.fingerprint for block in new}
    for old in held:
        if old.fingerprint in same:
            continue
        candidates = [
            block
            for block in new
            if block.issuer == old.issuer
            and block.selection == old.selection
            and block.this_update > old.this_update
            and block.next_update >= old.next_update
        ]
        if any(block.this_update <= when for block in candidates):
            continue
        if candidates:
            reason = (
                f"its CRL from issuer {old.issuer!r} is not in effect until "
                f"{min(b.this_update for b in candidates).isoformat()}"
            )
            return reason, True
        reason = (
            f"it carries no CRL from issuer {old.issuer!r} that OpenSSL would choose over the one "
            f"the running hop holds (thisUpdate {old.this_update.isoformat()}, nextUpdate "
            f"{old.next_update.isoformat()}). A superseding CRL must have a later thisUpdate, a "
            "nextUpdate no earlier, and the same scope, signing key and critical extensions. A "
            "running hop can only add CRLs"
        )
        return reason, False
    return None


def _certificates_in(copy: Path, *, label: str) -> set[bytes]:
    """The DER of each certificate in the CRL file at ``copy``, read on a scratch context.

    A load into the live context cannot be undone, so this is where a planted certificate is found
    (BACKLOG #1890). A non-CA certificate refuses: the live store's own list (``get_ca_certs``) holds
    only CA certificates, so one could never be proved already trusted. Raises ``ValueError``."""
    scratch = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # loads no roots: the count starts at zero
    scratch.load_verify_locations(cafile=str(copy))  # cafile= ONLY, as harden_crl_check says
    stats = scratch.cert_store_stats()
    if stats.get("crl", 0) < 1:
        raise ValueError(f"{label} loaded no CRL into a trust store")
    certificates = set(scratch.get_ca_certs(binary_form=True))
    if stats["x509"] != len(certificates):
        raise _NotProvable(
            f"{label} carries a certificate that is not a CA certificate, which a running hop "
            "cannot prove it already trusts. Give this setting a bare CRL (BACKLOG #1890)"
        )
    return certificates


class _NotProvable(ValueError):
    """A certificate in the file the reload cannot prove the hop already trusts. A start counts the
    store instead, so it may accept what this refuses, and the remedy says so."""


class _Refusals:
    """The first refusal of a pass for one file, kept whole, and whether every one was sticky."""

    def __init__(self) -> None:
        self.first: tuple[str, str] | None = None
        self.sticky = True

    def add(self, reason: str, remedy: str, *, sticky: bool = True) -> None:
        self.first = self.first or (reason, remedy)
        self.sticky = self.sticky and sticky


def _reload_path(
    path: str, pairs: list[tuple[ssl.SSLContext, HeldCrl]], now: float
) -> ReloadOutcome | None:
    """Bring every context in ``pairs`` that holds an older copy of ``path`` up to the file."""
    try:
        pem = Path(path).read_bytes()
    except OSError:
        # The expiry monitor reports an unreadable file and judges the held copy instead. The held
        # copy stays exactly as it is, which is the fail-closed outcome.
        log.debug("crl_reload: %s could not be read; running hops keep their copy", path)
        return None
    fingerprint = crl_fingerprint(pem)
    stale = [(ctx, held) for ctx, held in pairs if held.fingerprint != fingerprint]
    if not stale:
        clear_reload_refusal(path)
        return None
    prior = reload_refusal(path, fingerprint)
    if prior is not None and prior.sticky:
        # Nothing but a change to the file can alter this verdict, so these bytes are not judged
        # again. A refusal time can lift is retried every pass.
        return ReloadOutcome(path, 0, prior)
    shown = next((h.configured_path for _, h in stale if h.configured_path), path)
    label = crl_label(shown, next((h.setting for _, h in stale if h.setting), None))
    refusals = _Refusals()
    reloaded = 0
    try:
        facts, blocks = judge_crl_bytes(pem, label=label, now=now)
        # The cheap rules first: a rollback refuses every context without touching a file.
        verdicts: dict[tuple[CrlBlock, ...], tuple[str, bool] | None] = {}
        ready: list[tuple[ssl.SSLContext, HeldCrl]] = []
        for ctx, held in stale:
            if held.reloads >= MAX_RELOADS:
                refusals.add(
                    f"{label}: this hop has taken {held.reloads} CRL reloads, and each one stays in "
                    "its trust store",
                    RESTART,
                )
                continue
            if held.blocks not in verdicts:
                verdicts[held.blocks] = supersede_refusal(held.blocks, blocks, now=now)
            verdict = verdicts[held.blocks]
            if verdict is None:
                ready.append((ctx, held))
            else:
                why, waiting = verdict
                refusals.add(f"{label}: {why}", WAIT if waiting else RESTART, sticky=not waiting)
        if ready:
            with tempfile.TemporaryDirectory(prefix="mefor-crl-") as private:
                # The live load reads this private copy of the judged bytes, never the operator's
                # file a second time, so a file swapped after the judgement cannot reach a context.
                copy = Path(private) / "crl.pem"
                copy.write_bytes(pem)
                certificates = _certificates_in(copy, label=label)
                for ctx, held in ready:
                    if certificates and certificates - set(ctx.get_ca_certs(binary_form=True)):
                        refusals.add(
                            f"{label} carries a certificate this hop does not already trust; "
                            "loading it would make it a trust anchor. Give this setting a bare "
                            "CRL (BACKLOG #1890)",
                            FIX,
                        )
                        continue
                    ctx.load_verify_locations(
                        cafile=str(copy)
                    )  # cafile= ONLY: cadata= loads no CRL
                    reloaded += replace_held_copy(
                        ctx,
                        held,
                        replace(
                            held,
                            fingerprint=fingerprint,
                            facts=facts,
                            blocks=blocks,
                            reloads=held.reloads + 1,
                        ),
                    )
    except _NotProvable as exc:
        refusals.add(
            str(exc),
            "Give this setting a bare CRL. A restart applies the file only if the hop already "
            "trusts that certificate",
        )
    except (ValueError, ssl.SSLError) as exc:
        # The file fails a rule a start applies, or OpenSSL will not load it, so a restart would
        # refuse it too. An SSLError is an OSError, so it is caught before the clause below.
        refusals.add(f"{label}: {exc}" if isinstance(exc, ssl.SSLError) else str(exc), FIX)
    except OSError as exc:
        # The private copy could not be written: nothing about the file, so retry next pass.
        refusals.add(f"{label}: the reload could not stage the file ({exc})", RESTART, sticky=False)
    if reloaded:
        log.info(
            "crl_reload: applied %s to %d running TLS context(s) without a restart", label, reloaded
        )
    if refusals.first is None:
        clear_reload_refusal(path)
        return ReloadOutcome(path, reloaded, None)
    reason, remedy = refusals.first
    refusal = ReloadRefusal(fingerprint, reason, remedy, refusals.sticky)
    record_reload_refusal(path, refusal)
    if prior is None or prior.reason != reason:
        # Once per file version: a retried pass repeats every minute, and the monitor carries it.
        log.error(
            "crl_reload: refused to apply the replaced CRL file to %d running TLS context(s), "
            "which keep the copy they hold: %s. %s",
            len(stale) - reloaded,
            reason,
            remedy,
        )
    return ReloadOutcome(path, reloaded, refusal)


def reload_replaced_crls(*, now: float | None = None) -> list[ReloadOutcome]:
    """One pass: apply every replaced CRL file to the running contexts holding an older copy.

    Synchronous and blocking (file reads, CRL parsing, a context load), so the engine runs it in a
    worker thread. Returns one :class:`ReloadOutcome` per file some context held an older copy of. A
    failure on one file is logged and does not stop the others."""
    now = time.time() if now is None else now
    by_path: dict[str, list[tuple[ssl.SSLContext, HeldCrl]]] = {}
    for ctx, held in held_contexts():
        by_path.setdefault(held.path_key, []).append((ctx, held))
    outcomes: list[ReloadOutcome] = []
    for path, pairs in by_path.items():
        try:
            outcome = _reload_path(path, pairs, now)
        except Exception:
            log.error("crl_reload: could not check %s for a replacement", path, exc_info=True)
            continue
        if outcome is not None:
            outcomes.append(outcome)
    return outcomes


class CrlReloadRunner:
    """Runs :func:`reload_replaced_crls` every ``interval_seconds``, off the event loop.

    Engine-owned like the expiry monitor, but not gated on ``[cert_monitor]``: turning the alert off
    must not also stop revocations reaching a running hop. Not leader-gated: each process holds its
    own contexts."""

    def __init__(
        self,
        *,
        interval_seconds: float = RELOAD_INTERVAL_SECONDS,
        reload: Callable[[], object] = reload_replaced_crls,
    ) -> None:
        self._interval = interval_seconds
        self._reload = reload
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

    def start(self) -> None:
        """Spawn the loop (idempotent)."""
        if self._task is not None:
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        """Signal the loop and await its exit (idempotent).

        The task is NOT cancelled. A cancel would return at once while the worker thread, which
        cannot be cancelled, went on loading CRLs into live contexts after the engine stopped, and
        could overlap the pass of a runner started next. So a pass in flight finishes first."""
        self._stop.set()
        task = self._task
        self._task = None
        if task is not None:
            await task

    async def _run(self) -> None:
        # Sleep first: every context was just built from the file as it is now.
        while not self._stop.is_set():
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._stop.wait(), self._interval)
            if self._stop.is_set():
                return
            try:
                await asyncio.to_thread(self._reload)
            except Exception:
                log.exception("crl_reload pass failed; will retry next interval")
