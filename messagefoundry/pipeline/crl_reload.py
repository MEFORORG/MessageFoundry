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
``nextUpdate``, is not a delta CRL, none has expired, and no issuer has only CRLs not yet in effect.
Then it must carry no certificate the hop does not already trust (BACKLOG #1890). A load cannot be
undone, so that is proved on a scratch context BEFORE the live one sees the bytes. Each CRL's
signature must also verify against a CA certificate the hop lists for its issuer
(:func:`~messagefoundry.pki.crl_signature_refusal`). OpenSSL checks that signature only at the
handshake, so a badly signed CRL would otherwise load cleanly and then fail every handshake it judges.
The hop's list holds only its own trust store. An intermediate CA the peer sends in its handshake is
not in it, so a CRL that intermediate issued is refused with :data:`NO_ISSUER`. That refusal is
retried every pass, because a CA directory adds a CA to the store only when a handshake first needs
it. The live context then loads a private copy of the judged bytes in a directory only this account
can write, never the operator's file a second time. There is no check after the live load: a certificate
count read then races the lazy loading of a hashed root directory, and nothing found there could be
undone anyway. A refusal is logged at ERROR once per file version and recorded, so the expiry monitor
says why the hop's copy is still old. The old copy keeps its ``crl_expiry`` alert.

**One refusal is reported per file, the strongest.** Hops holding one file can need different things.
A file to fix outranks a restart, and both outrank a wait (:data:`_PRECEDENCE`), because waiting would
not apply the file. So a file not yet in effect is still checked for everything else. Where a restart
is the remedy but the file is not in effect yet, the reason says a start before then refuses it too.
A failure inside one context is that context's refusal alone: the others are still tried, and it is
retried next pass.

**A CRL up to five minutes ahead counts as in effect**
(:data:`~messagefoundry.config.tls_policy.CRL_CLOCK_SKEW_SECONDS`), at a start and here alike, so a
CA's clock running a little fast does not hold a reload back.

**A context's trust store only grows.** Each reload adds the file's CRLs and nothing removes the old
ones, so memory and per-handshake CRL scoring grow with every reload. ``[cert_monitor].crl_max_reloads``
bounds it (default :data:`MAX_RELOADS`): a context that has taken that many reloads for one file
refuses the next, and a restart starts it afresh. ``docs/CONFIGURATION.md`` gives the measured cost
under that key.

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
One lock serialises passes, so a pass left running by a stopped runner never overlaps the next.

**A pass is cheap when nothing changed.** With no CRL load recorded, the runner starts no thread. It
reads each held file's size, modification time and file id, and reads the bytes only when one of
those changed. It collects garbage only when some file needs a reload, so a context that is gone but
caught in a reference cycle is not reloaded.

Engine-side and stdlib plus ``cryptography`` (through :mod:`messagefoundry.pki`). It reads CRLs and
public CA certificates, never key material or message content.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime
import functools
import gc
import logging
import os
import shutil
import ssl
import tempfile
import threading
import time
from collections.abc import Callable, Collection, Sequence
from dataclasses import dataclass, replace
from pathlib import Path

from messagefoundry.config.loaded_crls import (
    HeldCrl,
    ReloadRefusal,
    clear_reload_refusal,
    crl_fingerprint,
    has_held_copies,
    held_contexts,
    prune_reload_refusals,
    record_reload_refusal,
    reload_refusal,
    replace_held_copy,
)
from messagefoundry.config.tls_policy import (
    crl_in_effect,
    crl_label,
    crl_not_in_effect,
    judge_crl_bytes,
)
from messagefoundry.pki import CrlBlock, CrlFacts, crl_signature_refusal

__all__ = [
    "BAD_SIGNATURE",
    "FIX",
    "LAPSES_FIRST",
    "MAX_RELOADS",
    "NO_ISSUER",
    "RELOAD_INTERVAL_SECONDS",
    "RESTART",
    "RETRY",
    "STOP_TIMEOUT_SECONDS",
    "WAIT",
    "CrlReloadRunner",
    "ReloadOutcome",
    "reload_replaced_crls",
    "supersede_refusal",
]

log = logging.getLogger(__name__)

#: How often the engine looks for a replaced CRL file. A pass reads each held file's metadata and
#: does nothing more unless a file changed, so a minute is cheap, and it bounds how long a revocation
#: added to the file goes unenforced by a new handshake on a running hop.
RELOAD_INTERVAL_SECONDS = 60.0

#: The default of ``[cert_monitor].crl_max_reloads``: reloads one context takes for one file before it
#: refuses and asks for a restart. It outlasts a year of hourly CRLs (8,760).
MAX_RELOADS = 10_000

#: How long :meth:`CrlReloadRunner.stop` waits for a pass in flight before it abandons it.
STOP_TIMEOUT_SECONDS = 10.0

#: The remedies a refusal carries. A refusal names exactly one, chosen where the refusal is made.
RESTART = "Restart the engine to apply the file"
FIX = "Fix the file: the engine would refuse to start on it too"
WAIT = (
    "Wait: the engine applies the file once its CRL takes effect. Do not restart before then: a "
    "start would refuse the file, or not use that CRL yet. If that CRL is from an issuer the hop "
    "does not hold yet, taking it out applies the rest of the file now"
)
LAPSES_FIRST = (
    "Fix the file now with a CRL that is in effect: the hop's copy lapses before the file's CRL "
    "takes effect, and every peer is refused in between, restart or not"
)
BAD_SIGNATURE = (
    "Fix the file: give a CRL the hop's CA signed. A restart would load it, and every handshake it "
    "judges would then fail"
)
NO_ISSUER = (
    "Restart the engine to apply the file. The reload checks a CRL's signature against the hop's "
    "own trust store, which does not hold an intermediate CA the peer sends in its handshake, nor "
    "always a CA from a CA directory or the system store. Where the hop has its own CA file, add "
    "the issuing intermediate to it, so later reloads can verify the CRL without a restart"
)
RETRY = "The engine tries again every pass. Restart the engine to apply the file now"
_NOT_PROVABLE = (
    "Give this setting a bare CRL. A restart applies the file only if the hop already trusts that "
    "certificate"
)
#: The refusals the reload judges again on the next pass, for the same bytes. Time can lift a
#: WAIT. A CA directory adds a CA to the trust store only when a handshake first needs it, so a
#: CA the reload could not list can appear later, which is why :data:`NO_ISSUER` is here too.
_RETRIED = frozenset({WAIT, LAPSES_FIRST, RETRY, NO_ISSUER})
#: Which remedy a refusal names when the contexts of one file disagree: the earliest here. A file
#: to fix, then a restart, outrank a wait, because waiting would not apply the file.
#: :data:`LAPSES_FIRST` is a fix too, and the most urgent one: every peer is refused, restart or not.
_PRECEDENCE = (FIX, BAD_SIGNATURE, _NOT_PROVABLE, LAPSES_FIRST, RESTART, NO_ISSUER, RETRY, WAIT)
_RANK = {remedy: rank for rank, remedy in enumerate(_PRECEDENCE)}
#: The remedies that say only time is missing.
_TIME_ONLY = frozenset({WAIT, LAPSES_FIRST})
#: The remedies that send the operator to a restart, which fails while the file is not in effect.
_SAYS_RESTART = frozenset({RESTART, NO_ISSUER, RETRY, _NOT_PROVABLE})


@dataclass(frozen=True)
class ReloadOutcome:
    """What one pass did for one CRL file that a running context held an older copy of."""

    path: str
    #: Contexts now checking against the file.
    reloaded: int
    #: Why some or all of the stale contexts kept their old copy, or ``None`` when none did.
    refusal: ReloadRefusal | None


def _first_lapse(held: Sequence[CrlBlock]) -> CrlBlock | None:
    """The held CRL whose ``nextUpdate`` first ends what the hop checks some peer against.

    OpenSSL scores CRLs per issuer and per ``selection`` (scope and signing key), and among equals
    uses the latest ``thisUpdate``. So each such group lapses with its latest CRL. An older CRL in
    the group that lapses sooner changes nothing, and one that lapses later would only stand in
    without the newer revocations. The soonest of those latest CRLs decides."""
    latest: dict[tuple[str, tuple[bytes | None, bytes | None, frozenset[str]]], CrlBlock] = {}
    for block in held:
        group = (block.issuer, block.selection)
        if group not in latest or block.this_update > latest[group].this_update:
            latest[group] = block
    return min(latest.values(), key=lambda block: block.next_update, default=None)


def _waiting(
    held: Sequence[CrlBlock], issuer: str, takes_effect: datetime.datetime
) -> tuple[str, str]:
    """The reason and remedy for a file that applies only once its CRL from ``issuer`` takes
    effect at ``takes_effect``.

    Nothing in the file reaches the hop until then, so waiting is right only when every CRL the
    hop holds lasts that long (:func:`_first_lapse`), whatever its issuer. When one lapses first,
    the hop refuses its peers in between, so the file must change instead."""
    reason = f"its CRL from issuer {issuer!r} is not in effect until {takes_effect.isoformat()}"
    lapsing = _first_lapse(held)
    if lapsing is not None and lapsing.next_update < takes_effect:
        return (
            f"{reason}, and the hop's CRL from issuer {lapsing.issuer!r} lapses earlier, at "
            f"{lapsing.next_update.isoformat()}"
        ), LAPSES_FIRST
    return reason, WAIT


def supersede_refusal(
    held: Sequence[CrlBlock], new: Sequence[CrlBlock], *, now: float
) -> tuple[str, str] | None:
    """Why adding ``new`` to a context holding ``held`` would NOT leave it checking exactly ``new``,
    and the remedy, or ``None`` when it would. The module docstring gives the rule. The remedy is
    :data:`WAIT` or :data:`LAPSES_FIRST` when the only thing missing is time: the file has a
    superseding CRL that is not in effect yet, or an issuer with none in effect yet. The file
    applies once the last of those takes effect. A held CRL nothing supersedes outranks a wait,
    since waiting would not apply the file."""
    if not held:
        reason = (
            "the CRLs of the running copy were not recorded, so the engine cannot prove the file "
            "supersedes them"
        )
        return reason, RESTART
    same = {block.fingerprint for block in new}
    for old in held:
        if old.fingerprint in same or _successors(old, new):
            continue
        reason = (
            f"it carries no CRL from issuer {old.issuer!r} that OpenSSL would choose over the one "
            f"the running hop holds (thisUpdate {old.this_update.isoformat()}, nextUpdate "
            f"{old.next_update.isoformat()}). A superseding CRL must have a later thisUpdate, a "
            "nextUpdate no earlier, and the same scope, signing key and critical extensions. A "
            "running hop can only add CRLs"
        )
        return reason, RESTART
    return _time_verdict(held, new, now=now)


def _successors(old: CrlBlock, new: Sequence[CrlBlock]) -> list[CrlBlock]:
    """The CRLs in ``new`` OpenSSL would choose over ``old`` once they are in effect."""
    return [
        block
        for block in new
        if block.issuer == old.issuer
        and block.selection == old.selection
        and block.this_update > old.this_update
        and block.next_update >= old.next_update
    ]


def _time_verdict(
    held: Sequence[CrlBlock], new: Sequence[CrlBlock], *, now: float
) -> tuple[str, str] | None:
    """:data:`WAIT` or :data:`LAPSES_FIRST` when ``new`` can reach a context holding ``held`` only
    once some CRL in it takes effect, else ``None``. That is a superseding CRL not in effect yet,
    or an issuer with none in effect yet. The file applies once the last of those takes effect."""
    same = {block.fingerprint for block in new}
    waits: list[CrlBlock] = []
    if (unmet := crl_not_in_effect(new, now=now)) is not None:
        waits.append(unmet)
    for old in held:
        candidates = [] if old.fingerprint in same else _successors(old, new)
        if candidates and not any(crl_in_effect(block, now=now) for block in candidates):
            waits.append(min(candidates, key=lambda block: block.this_update))
    if not waits:
        return None
    last = max(waits, key=lambda block: block.this_update)
    return _waiting(held, last.issuer, last.this_update)


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
    """The refusal of a pass for one file that outranks the rest (:data:`_PRECEDENCE`, the first
    among equals), kept whole, and whether every one was sticky."""

    def __init__(self) -> None:
        self.strongest: tuple[str, str] | None = None
        self.sticky = True
        #: An unexpected failure, logged with its traceback once per file version.
        self.error: BaseException | None = None

    def add(self, reason: str, remedy: str) -> None:
        if self.strongest is None or _RANK[remedy] < _RANK[self.strongest[1]]:
            self.strongest = (reason, remedy)
        self.sticky = self.sticky and remedy not in _RETRIED


# Pass state, touched only under _PASS_LOCK. Keyed by path key, pruned to the held paths each pass.
_PASS_LOCK = threading.Lock()
#: The (size, mtime_ns, file id) last seen for each held file, and the fingerprint of its bytes then.
_SEEN: dict[str, tuple[tuple[int, int, int], tuple[int, int]]] = {}
#: Held files that could not be read, so the warning is logged once until one can be read again.
_UNREADABLE: set[str] = set()
#: The last unexpected failure per file outside a judged version, so its traceback is logged once.
_FAILED: dict[str, str] = {}


def _read_path(pairs: Sequence[tuple[ssl.SSLContext, HeldCrl]]) -> str:
    """The path to read: as configured, case kept. The key is case-folded on Windows."""
    return pairs[0][1].file_path


def _stamp(path: str) -> tuple[int, int, int]:
    st = os.stat(path)
    return st.st_size, st.st_mtime_ns, st.st_ino


def _unreadable(key: str, path: str, exc: OSError) -> None:
    # The expiry monitor reports an unreadable file and judges the held copy instead. The held copy
    # stays exactly as it is, which is the fail-closed outcome.
    if key not in _UNREADABLE:
        _UNREADABLE.add(key)
        log.warning(
            "crl_reload: %s could not be read (%s); running hops keep their copy",
            path,
            exc.strerror or type(exc).__name__,
        )


def _read(
    key: str, path: str, stamp: tuple[int, int, int] | None = None
) -> tuple[bytes, tuple[int, int]] | None:
    """The file's bytes and fingerprint, recording its stamp, or ``None`` when it cannot be read
    (logged once). ``stamp`` is one just taken, so the file is not stat'd twice."""
    try:
        stamp = stamp or _stamp(path)  # before the read: a change during it shows up next pass
        pem = Path(path).read_bytes()
    except OSError as exc:
        _unreadable(key, path, exc)
        return None
    _UNREADABLE.discard(key)
    fingerprint = crl_fingerprint(pem)
    _SEEN[key] = (stamp, fingerprint)
    return pem, fingerprint


@dataclass(frozen=True)
class _Change:
    """A held file whose bytes differ from some context's copy and are not refused for good."""

    #: The bytes, or ``None`` when the stamp was unchanged and they were not read this pass.
    pem: bytes | None
    fingerprint: tuple[int, int]
    #: True when these bytes were refused before, for a reason time can lift.
    retry: bool


def _triage(
    key: str, pairs: Sequence[tuple[ssl.SSLContext, HeldCrl]]
) -> ReloadRefusal | _Change | None:
    """``None`` when every context holds the file as it is (or it cannot be read), a sticky
    :class:`ReloadRefusal` when those bytes were refused already, else the :class:`_Change`."""
    path = _read_path(pairs)
    try:
        stamp = _stamp(path)
    except OSError as exc:
        _unreadable(key, path, exc)
        return None
    seen = _SEEN.get(key)
    pem: bytes | None = None
    if seen is not None and seen[0] == stamp:
        _UNREADABLE.discard(key)
        fingerprint = seen[1]
    elif (read := _read(key, path, stamp)) is not None:
        pem, fingerprint = read
    else:
        return None
    if all(held.fingerprint == fingerprint for _, held in pairs):
        clear_reload_refusal(key)
        return None
    prior = reload_refusal(key, fingerprint)
    if prior is not None and prior.sticky:
        # Nothing but a change to the file can alter this verdict, so these bytes are not judged
        # again. A refusal time can lift is retried every pass.
        return prior
    return _Change(pem, fingerprint, retry=prior is not None)


def _reload_path(
    key: str,
    pairs: list[tuple[ssl.SSLContext, HeldCrl]],
    change: _Change,
    now: float,
    max_reloads: int,
) -> ReloadOutcome | None:
    """Bring every context in ``pairs`` that holds an older copy of the file up to the file."""
    path = _read_path(pairs)
    pem, fingerprint = change.pem, change.fingerprint
    if pem is None:
        # A retried refusal whose file is unchanged: read the bytes the triage did not.
        if (read := _read(key, path)) is None:
            return None
        pem, fingerprint = read
    stale = [(ctx, held) for ctx, held in pairs if held.fingerprint != fingerprint]
    if not stale:
        clear_reload_refusal(key)
        return None
    prior = reload_refusal(key, fingerprint)
    shown = next((h.configured_path for _, h in stale if h.configured_path), path)
    label = crl_label(shown, next((h.setting for _, h in stale if h.setting), None))
    refusals = _Refusals()
    reloaded = 0
    blocks: tuple[CrlBlock, ...] = ()  # stays empty when the bytes cannot be judged
    try:
        # A CRL not in effect yet is judged here, not refused there: a context at the cap, a held
        # CRL nothing supersedes, or a file to fix each outranks a wait, and must be reported.
        facts, blocks = judge_crl_bytes(pem, label=label, now=now, require_in_effect=False)
        # The cheap rules first: a rollback refuses every context without touching a file.
        verdicts: dict[tuple[CrlBlock, ...], tuple[str, str] | None] = {}
        timing: dict[tuple[CrlBlock, ...], tuple[str, str] | None] = {}
        ready: list[tuple[ssl.SSLContext, HeldCrl, tuple[str, str] | None]] = []
        for ctx, held in stale:
            # First, for every context: does some CRL it holds lapse before the file can apply?
            # That outranks every other verdict below, so no other path may hide it.
            if held.blocks not in timing:
                timing[held.blocks] = _time_verdict(held.blocks, blocks, now=now)
            if (late := timing[held.blocks]) is not None and late[1] == LAPSES_FIRST:
                refusals.add(f"{label}: {late[0]}", LAPSES_FIRST)
            if held.reloads >= max_reloads:
                refusals.add(
                    f"{label}: this hop has taken {held.reloads} CRL reloads, and each one stays in "
                    "its trust store ([cert_monitor].crl_max_reloads)",
                    RESTART,
                )
                continue
            if held.blocks not in verdicts:
                verdicts[held.blocks] = supersede_refusal(held.blocks, blocks, now=now)
            wait = verdicts[held.blocks]
            if wait is not None and wait[1] not in _TIME_ONLY:
                refusals.add(f"{label}: {wait[0]}", wait[1])
                continue
            ready.append((ctx, held, wait))
        if ready:
            reloaded = _load(pem, label, ready, refusals, fingerprint, facts, blocks)
    except _NotProvable as exc:
        refusals.add(str(exc), _NOT_PROVABLE)
    except (ValueError, ssl.SSLError) as exc:
        # The file fails a rule a start applies, or OpenSSL will not load it, so a restart would
        # refuse it too. An SSLError is an OSError, so it is caught before the clause below.
        refusals.add(f"{label}: {exc}" if isinstance(exc, ssl.SSLError) else str(exc), FIX)
    except OSError as exc:
        # The private copy could not be written: nothing about the file, so retry next pass. The
        # reason leaves out the random path, so the once-per-version log stays once.
        refusals.add(
            f"{label}: the reload could not stage the file ({exc.strerror or type(exc).__name__})",
            RETRY,
        )
    except Exception as exc:
        # A defect, not a verdict on the file. Retried every pass, its traceback logged once.
        refusals.add(f"{label}: the reload failed unexpectedly ({type(exc).__name__})", RETRY)
        refusals.error = exc
    if (
        refusals.strongest is not None
        and refusals.strongest[1] in _SAYS_RESTART
        and (unmet := crl_not_in_effect(blocks, now=now)) is not None
    ):
        why, remedy = refusals.strongest
        refusals.strongest = (
            f"{why}. Not before {unmet.this_update.isoformat()}: a start until then refuses this "
            f"file too, since its CRL from issuer {unmet.issuer!r} is not in effect",
            remedy,
        )
        # Judged again each pass, so the warning goes once its time has passed.
        refusals.sticky = False
    return _finish(label, path, fingerprint, stale, reloaded, refusals, prior)


def _load(
    pem: bytes,
    label: str,
    ready: list[tuple[ssl.SSLContext, HeldCrl, tuple[str, str] | None]],
    refusals: _Refusals,
    fingerprint: tuple[int, int],
    facts: CrlFacts,
    blocks: tuple[CrlBlock, ...],
) -> int:
    """Load the judged bytes into each context in ``ready`` that passes the per-context checks.

    A context paired with a wait gets the checks and then the wait, so a file to fix is reported
    as one even before it takes effect. Returns how many contexts now hold the file. A failure in
    one context is that context's refusal alone, retried next pass: the contexts already loaded
    stay counted, and the rest are still tried."""
    reloaded = 0
    private = tempfile.mkdtemp(prefix="mefor-crl-")  # mode 0o700: only this account writes it
    try:
        # The live load reads this private copy of the judged bytes, never the operator's file a
        # second time, so a file swapped after the judgement cannot reach a context.
        copy = Path(private) / "crl.pem"
        copy.write_bytes(pem)
        certificates = _certificates_in(copy, label=label)
        signatures: dict[frozenset[bytes], tuple[str, bool] | None] = {}
        for ctx, held, wait in ready:
            try:
                anchors = frozenset(ctx.get_ca_certs(binary_form=True))
                if certificates - anchors:
                    refusals.add(
                        f"{label} carries a certificate this hop does not already trust; loading "
                        "it would make it a trust anchor. Give this setting a bare CRL (BACKLOG "
                        "#1890)",
                        FIX,
                    )
                    continue
                if anchors not in signatures:
                    signatures[anchors] = crl_signature_refusal(pem, anchors)
                if (unsigned := signatures[anchors]) is not None:
                    why, found = unsigned
                    refusals.add(f"{label}: {why}", BAD_SIGNATURE if found else NO_ISSUER)
                    continue
                if wait is not None:
                    refusals.add(f"{label}: {wait[0]}", wait[1])
                    continue
                ctx.load_verify_locations(cafile=str(copy))  # cafile= ONLY: cadata= loads no CRL
            except Exception as exc:
                # Not a verdict on the file: the scratch context loaded these same bytes. So it
                # is never sticky, and one context's failure does not stop the others.
                refusals.add(
                    f"{label}: the reload failed for a running context ({type(exc).__name__})",
                    RETRY,
                )
                refusals.error = refusals.error or exc
                continue
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
    finally:
        try:
            shutil.rmtree(private)
        except OSError as exc:
            # The contexts already hold what they loaded, so this is not a refusal.
            log.warning("crl_reload: could not remove the private CRL copy %s: %s", private, exc)
    return reloaded


def _finish(
    label: str,
    path: str,
    fingerprint: tuple[int, int],
    stale: list[tuple[ssl.SSLContext, HeldCrl]],
    reloaded: int,
    refusals: _Refusals,
    prior: ReloadRefusal | None,
) -> ReloadOutcome:
    """Log and record what one file's reload did, and return it."""
    if reloaded:
        log.info(
            "crl_reload: applied %s to %d running TLS context(s) without a restart", label, reloaded
        )
    if refusals.strongest is None:
        clear_reload_refusal(path)
        return ReloadOutcome(path, reloaded, None)
    reason, remedy = refusals.strongest
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
            exc_info=refusals.error,
        )
    return ReloadOutcome(path, reloaded, refusal)


def _held_by_path() -> dict[str, list[tuple[ssl.SSLContext, HeldCrl]]]:
    by_path: dict[str, list[tuple[ssl.SSLContext, HeldCrl]]] = {}
    for ctx, held in held_contexts():
        by_path.setdefault(held.path_key, []).append((ctx, held))
    return by_path


def _failed(key: str, exc: Exception) -> None:
    """Log an unexpected failure for one file, with its traceback, once until it changes."""
    seen = f"{type(exc).__name__}: {exc}"
    if _FAILED.get(key) != seen:
        _FAILED[key] = seen
        log.error("crl_reload: could not check %s for a replacement", key, exc_info=exc)


def _pending() -> tuple[dict[str, _Change], list[ReloadOutcome]]:
    """The held paths whose file needs a reload, and an outcome for each one refused already.

    A function of its own so the contexts it reads are released when it returns, before the
    collection that may follow it."""
    by_path = _held_by_path()
    _prune(by_path)
    pending: dict[str, _Change] = {}
    refused: list[ReloadOutcome] = []
    for key, pairs in by_path.items():
        try:
            verdict = _triage(key, pairs)
        except Exception as exc:
            _failed(key, exc)
            continue
        if isinstance(verdict, ReloadRefusal):
            refused.append(ReloadOutcome(_read_path(pairs), 0, verdict))
        elif verdict is not None:
            pending[key] = verdict
    return pending, refused


def _prune(held: Collection[str]) -> None:
    """Drop the pass state and the refusals of every path key not in ``held``. Under the pass lock."""
    for state in (_SEEN, _FAILED):
        for gone in [key for key in state if key not in held]:
            del state[gone]
    _UNREADABLE.intersection_update(held)
    prune_reload_refusals(held)


def _forget_all() -> None:
    """:func:`_prune` everything, when no hop holds any CRL. Never waits on the pass lock: it runs
    on the event loop, and a pass abandoned by :meth:`CrlReloadRunner.stop` may still hold it, in
    which case the next pass prunes instead."""
    if not _PASS_LOCK.acquire(blocking=False):
        return
    try:
        _prune(())
    finally:
        _PASS_LOCK.release()


def reload_replaced_crls(
    *, now: float | None = None, max_reloads: int = MAX_RELOADS
) -> list[ReloadOutcome]:
    """One pass: apply every replaced CRL file to the running contexts holding an older copy.

    Synchronous and blocking (file reads, CRL parsing, a context load), so the engine runs it in a
    worker thread. Returns one :class:`ReloadOutcome` per file some context held an older copy of. A
    failure on one file is logged and does not stop the others."""
    now = time.time() if now is None else now
    with _PASS_LOCK:
        pending, outcomes = _pending()
        if not pending:
            return outcomes
        if not all(change.retry for change in pending.values()):
            # A context in a reference cycle stays in the weak registry until collected. Collect
            # only when a file has newly changed, as the expiry monitor does before its scan, and
            # not on every retry of a refusal time can lift.
            gc.collect()
        current = _held_by_path()
        for key, change in pending.items():
            if key not in current:
                continue
            try:
                outcome = _reload_path(key, current[key], change, now, max_reloads)
            except Exception as exc:
                _failed(key, exc)
                continue
            _FAILED.pop(key, None)
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
        max_reloads: int = MAX_RELOADS,
        reload: Callable[[], object] | None = None,
        stop_timeout_seconds: float = STOP_TIMEOUT_SECONDS,
        skip_when_idle: bool = True,
    ) -> None:
        self._interval = interval_seconds
        self._reload = reload or functools.partial(reload_replaced_crls, max_reloads=max_reloads)
        # With no CRL load recorded there is nothing to reload, so no worker thread is started.
        self._skip_when_idle = skip_when_idle
        self._stop_timeout = stop_timeout_seconds
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

    def start(self) -> None:
        """Spawn the loop (idempotent)."""
        if self._task is not None:
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        """Signal the loop and await its exit, for at most ``stop_timeout_seconds`` (idempotent).

        A pass in flight gets that long to finish, so it does not go on loading CRLs after the engine
        stopped. A pass that takes longer, such as a read hung on a network share, is abandoned: the
        task is cancelled, and its worker thread, which cannot be cancelled, finishes on its own. A
        pass lock keeps it from overlapping a runner started next."""
        self._stop.set()
        task = self._task
        self._task = None
        if task is None:
            return
        try:
            done, _ = await asyncio.wait({task}, timeout=self._stop_timeout)
        except asyncio.CancelledError:
            task.cancel()
            raise
        if not done:
            log.warning(
                "crl_reload: a reload pass did not finish within %gs of stop; abandoning it",
                self._stop_timeout,
            )
            task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    async def _run(self) -> None:
        # Sleep first: every context was just built from the file as it is now.
        while not self._stop.is_set():
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._stop.wait(), self._interval)
            if self._stop.is_set():
                return
            if self._skip_when_idle and not has_held_copies():
                _forget_all()
                continue
            try:
                await asyncio.to_thread(self._reload)
            except Exception:
                log.exception("crl_reload pass failed; will retry next interval")
