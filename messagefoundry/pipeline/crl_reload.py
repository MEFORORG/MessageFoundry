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
Adding is enough, because of how OpenSSL picks a CRL, measured on CPython 3.14 / OpenSSL 3.5.7: among
the CRLs a store holds for one issuer it uses a current one, and among current ones the latest
``thisUpdate``. A context holding a clean CRL and then given a newer one that revokes the peer refuses
the peer, in either load order. So once the new CRL is in the store, OpenSSL uses it.

**That holds only when the new file supersedes every CRL the context already holds.** For each CRL the
running copy carries, the file must carry the same CRL, or one from the same issuer with a later
``thisUpdate`` that is already in effect and a ``nextUpdate`` no earlier. Then no held CRL can ever be
chosen over the file's, and the context checks exactly what the file says. A file that fails this, such
as a rollback to an older CRL or one that drops an issuer, is refused here, and a restart applies it.
The proof that one superseding step is enough for the next is transitivity: each held CRL is
superseded by the file that replaced it, and that file by the next one.

**Every refusal keeps the old copy, and fails closed.** The replacement must first pass the rules a
start applies (:func:`~messagefoundry.config.tls_policy.judge_crl_bytes`): every block parses, has a
``nextUpdate``, is not a delta CRL, and none has expired. Then it must carry no certificate the hop
does not already trust (BACKLOG #1890). A load cannot be undone, so that is proved on a scratch context
BEFORE the live one sees the bytes, and the live context loads a private copy of the judged bytes, never
the operator's file a second time. A refusal is logged at ERROR once per file version, and recorded so
the expiry monitor says why the hop's copy is still old (:func:`~messagefoundry.config.loaded_crls.
record_reload_refusal`). The old copy then keeps its ``crl_expiry`` alert.

**What this does not reach.** At least these, each of which still needs a restart: a CRL block inside
a CA bundle, which nothing records; a hop whose CRL load was not recorded (the Postgres store records
none, and needs no reload: it builds a fresh context per pool connection, so a new connection reads
the file); and a replacement this module refuses. A hop rebuilt by a config reload reads the file
itself.

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
from dataclasses import dataclass
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
from messagefoundry.pki import CrlBlock, read_crl_blocks

__all__ = [
    "RELOAD_INTERVAL_SECONDS",
    "CrlReloadRunner",
    "ReloadOutcome",
    "reload_replaced_crls",
    "supersede_refusal",
]

log = logging.getLogger(__name__)

#: How often the engine looks for a replaced CRL file. A pass reads each held CRL file once and does
#: nothing more unless a file changed, so a minute is cheap, and it bounds how long a revocation added
#: to the file goes unenforced by a running hop.
RELOAD_INTERVAL_SECONDS = 60.0


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
) -> str | None:
    """Why adding ``new`` to a context holding ``held`` would NOT leave it checking exactly ``new``, or
    ``None`` when it would. The module docstring gives the rule and why it suffices."""
    if not held:
        return (
            "the CRLs of the running copy were not recorded, so the engine cannot prove the file "
            "supersedes them"
        )
    when = datetime.datetime.fromtimestamp(now, tz=datetime.UTC)
    same = {block.fingerprint for block in new}
    for old in held:
        if old.fingerprint in same:
            continue
        if any(
            block.issuer == old.issuer
            and old.this_update < block.this_update <= when
            and block.next_update >= old.next_update
            for block in new
        ):
            continue
        return (
            f"it carries no CRL from issuer {old.issuer!r} that is already in effect, was issued "
            f"after the one the running hop holds (thisUpdate {old.this_update.isoformat()}), and "
            f"runs at least as long (nextUpdate {old.next_update.isoformat()}). A running hop can "
            "only add CRLs, and OpenSSL would go on choosing the one it holds"
        )
    return None


def _certificates_in(copy: Path, *, label: str) -> set[bytes]:
    """The DER of each certificate in the CRL file at ``copy``, read on a scratch context.

    A load into the live context cannot be undone, so this is where a planted certificate is found
    (BACKLOG #1890). A non-CA certificate refuses outright: the live store's own list
    (``get_ca_certs``) holds only CA certificates, so one could never be proved already trusted.
    Raises ``ValueError`` led by ``label``."""
    scratch = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # loads no roots: the count starts at zero
    scratch.load_verify_locations(cafile=str(copy))  # cafile= ONLY, as harden_crl_check says
    stats = scratch.cert_store_stats()
    if stats.get("crl", 0) < 1:
        raise ValueError(f"{label} loaded no CRL into a trust store")
    certificates = set(scratch.get_ca_certs(binary_form=True))
    if stats["x509"] != len(certificates):
        raise ValueError(
            f"{label} carries a certificate that is not a CA certificate. Give this setting a "
            "bare CRL (BACKLOG #1890)"
        )
    return certificates


def _apply(ctx: ssl.SSLContext, copy: Path, pem: bytes) -> None:
    """Add the CRL file at ``copy`` to the live ``ctx``. Raises ``RuntimeError`` if the trust store
    gained a certificate or the private copy changed, neither of which the checks before it allow."""
    before = ctx.cert_store_stats()["x509"]
    ctx.load_verify_locations(cafile=str(copy))  # cafile= ONLY: cadata= loads zero CRLs
    if ctx.cert_store_stats()["x509"] != before or copy.read_bytes() != pem:
        raise RuntimeError("the trust store changed in a way the checks before the load rule out")


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
    setting = next((held.setting for _, held in stale if held.setting), None)
    label = crl_label(path, setting)
    refusals: list[tuple[str, bool]] = []
    reloaded = 0
    try:
        facts = judge_crl_bytes(pem, label=label, now=now)
        blocks = tuple(read_crl_blocks(pem))
        with tempfile.TemporaryDirectory(prefix="mefor-crl-") as private:
            # The live load reads this private copy of the judged bytes, never the operator's file a
            # second time, so a file swapped after the judgement cannot reach a live context.
            copy = Path(private) / "crl.pem"
            copy.write_bytes(pem)
            certificates = _certificates_in(copy, label=label)
            for ctx, held in stale:
                why = supersede_refusal(held.blocks, blocks, now=now)
                if why is not None:
                    refusals.append((f"{label}: {why}", True))
                    continue
                if certificates - set(ctx.get_ca_certs(binary_form=True)):
                    refusals.append(
                        (
                            f"{label} carries a certificate this hop does not already trust; "
                            "loading it would make it a trust anchor. Give this setting a bare "
                            "CRL (BACKLOG #1890)",
                            False,
                        )
                    )
                    continue
                try:
                    _apply(ctx, copy, pem)
                except RuntimeError:
                    log.critical(
                        "crl_reload: %s changed a running hop's trust store unexpectedly while "
                        "it was being applied. Restart the engine",
                        label,
                        exc_info=True,
                    )
                    refusals.append((f"{label}: the reload failed; restart the engine", False))
                    continue
                replaced = HeldCrl(held.path_key, fingerprint, facts, held.setting, blocks)
                if replace_held_copy(ctx, held, replaced):
                    reloaded += 1
    except ValueError as exc:
        # The file fails a rule a start applies, so a restart would refuse it too.
        refusals.append((str(exc), False))
    if reloaded:
        log.info(
            "crl_reload: applied %s to %d running TLS context(s) without a restart", label, reloaded
        )
    if not refusals:
        clear_reload_refusal(path)
        return ReloadOutcome(path, reloaded, None)
    reason = refusals[0][0]
    refusal = ReloadRefusal(fingerprint, reason, all(applies for _, applies in refusals))
    prior = reload_refusal(path, fingerprint)
    record_reload_refusal(path, refusal)
    if prior is None or prior.reason != reason:
        # Once per file version: the pass repeats every minute, and the monitor carries it after.
        log.error(
            "crl_reload: refused to apply the replaced CRL file to %d running TLS context(s), "
            "which keep the copy they hold: %s. %s",
            len(stale) - reloaded,
            reason,
            "A restart applies the file"
            if refusal.restart_applies
            else "Fix the file: the engine would refuse to start on it too",
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
        """Signal the loop and await its exit (idempotent)."""
        self._stop.set()
        task = self._task
        self._task = None
        if task is not None:
            task.cancel()
            try:  # noqa: SIM105
                await task
            except asyncio.CancelledError:
                pass

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
