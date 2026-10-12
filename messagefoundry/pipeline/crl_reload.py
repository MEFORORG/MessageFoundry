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
handshake, so OpenSSL would load a badly signed CRL and then fail every handshake it judges. A start
checks the signature too, and refuses only the proven case: a CRL that names a listed CA's key and
is not signed by it (vault BACKLOG #2905). Anything short of that a start loads with a warning, so
this reload holds back some files a start would load.
The hop's list holds only its own trust store. An intermediate CA the peer sends in its handshake is
not in it, so a CRL that intermediate issued is refused with :data:`NO_ISSUER`. That refusal is
retried every pass, because a CA directory adds a CA to the store only when a handshake first needs
it. The live context then loads a private copy of the judged bytes in a directory only this account
can write, never the operator's file a second time. There is no check after the live load: a certificate
count read then races the lazy loading of a hashed root directory, and nothing found there could be
undone anyway. A refusal is logged at ERROR once per file version and recorded, so the expiry monitor
says why the hop's copy is still old. The old copy keeps its ``crl_expiry`` alert. That alert speaks
only once the held copy nears its ``nextUpdate``, so :class:`CrlReloadRunner` also raises
``crl_reload_refused`` for the refusal itself, once per file version (vault BACKLOG #2904).

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
* a CRL block inside a CA bundle. The expiry monitor judges the copy a hop loaded from one, but
  this pass skips it (vault BACKLOG #2319). Its rules are a CRL setting's, so a CA file that
  gained a CA would be refused as a file to fix, when the file is right and a restart applies it;
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
import binascii
import contextlib
import datetime
import functools
import gc
import logging
import os
import ssl
import threading
import time
from collections.abc import Callable, Collection, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import NamedTuple

from messagefoundry.config.loaded_crls import (
    HeldCrl,
    ReloadRefusal,
    clear_reload_refusal,
    crl_fingerprint,
    crl_path_key,
    has_held_copies,
    held_contexts,
    prune_reload_refusals,
    record_reload_refusal,
    reload_refusal,
    reload_refusals,
    replace_held_copy,
)
from messagefoundry.config.tls_policy import (
    crl_in_effect,
    crl_label,
    crl_not_in_effect,
    crl_scratch_context,
    judge_crl_bytes,
    staged_crl,
)
from messagefoundry.pipeline.alerts import AlertSink, LoggingAlertSink
from messagefoundry.pipeline.intake_bound import process_alert_subject
from messagefoundry.pki import CrlBlock, CrlFacts, crl_signature_refusal
from messagefoundry.redaction import log_timestamp

__all__ = [
    "ALERT_PATH_MAX_LENGTH",
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
    "reload_alert_subject",
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
#: True of both things a start does with such a file (vault BACKLOG #2905). A start refuses a CRL
#: that names the CA's key and is not signed by it. It loads any other with a warning, and the
#: handshake then decides. The reload gives this one remedy for all of those cases, because
#: :func:`~messagefoundry.pki.crl_signature_refusal` folds them into one flag. So it cannot
#: tell a renewed CA key, where a restart is enough, from a forged CRL. That is unfiled.
BAD_SIGNATURE = (
    "If the file is wrong, fix it: give a CRL the hop's CA signed. Where the CRL names that "
    "CA's key, a start refuses the file too. Otherwise a start loads it with a warning, and each "
    "handshake then decides. It passes where the peer's chain carries the CA that signed the "
    "CRL, as after a CA renews its key, and fails where it does not"
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
#: The refusals that can lift while the bytes stay the same. Time can lift a WAIT. A CA directory
#: adds a CA to the trust store only when a handshake first needs it, so a CA the reload could not
#: list can appear later, which is why :data:`NO_ISSUER` is here too. :attr:`_Refusals.sticky`
#: says when one of these makes the next pass judge the same bytes again.
_RETRIED = frozenset({WAIT, LAPSES_FIRST, RETRY, NO_ISSUER})
#: Which remedy a refusal names when the contexts of one file disagree: the earliest here. A file
#: to fix, then a restart, outrank a wait, because waiting would not apply the file.
#: :data:`LAPSES_FIRST` is a fix too, and the most urgent one: every peer is refused, restart or not.
_PRECEDENCE = (FIX, BAD_SIGNATURE, _NOT_PROVABLE, LAPSES_FIRST, RESTART, NO_ISSUER, RETRY, WAIT)
_RANK = {remedy: rank for rank, remedy in enumerate(_PRECEDENCE)}
#: The remedies that send the operator to a restart, which fails while the file is not in effect.
_SAYS_RESTART = frozenset({RESTART, NO_ISSUER, RETRY, _NOT_PROVABLE})
#: A short token per remedy, for the ``crl_reload_refused`` alert (vault BACKLOG #2904). The alert
#: carries this and the remedy sentence, never the refusal's reason, which quotes CRL issuer
#: names and dates. ``docs/CONFIGURATION.md`` lists the tokens under ``[cert_monitor]``.
_REMEDY_CLASS = {
    RESTART: "restart",
    FIX: "fix_file",
    WAIT: "wait",
    LAPSES_FIRST: "lapses_first",
    BAD_SIGNATURE: "bad_signature",
    NO_ISSUER: "no_issuer",
    RETRY: "retry",
    _NOT_PROVABLE: "not_provable",
}
#: The token for a remedy :data:`_REMEDY_CLASS` does not hold. No pass produces one today. The
#: alert then carries this token and no remedy sentence, so text the map does not vouch for
#: never reaches a notifier.
_OTHER_REMEDY_CLASS = "other"


def _remedy_class(remedy: str) -> str:
    """The alert's short token for ``remedy``. One rule, for the outcome and for the alert."""
    return _REMEDY_CLASS.get(remedy, _OTHER_REMEDY_CLASS)


#: The longest CRL path a ``crl_reload_refused`` alert subject carries whole. With the
#: ``crl_reload:`` prefix, that leaves
#: :func:`~messagefoundry.pipeline.intake_bound.process_alert_subject` room to add the process
#: label inside its own cap, which sits under the SQL Server store's 256-character
#: ``alert_instance.connection`` column.
ALERT_PATH_MAX_LENGTH = 120
#: Hex digits of the CRC-32 that stands in for the head of a longer path. A checksum, not a
#: cryptographic digest: the path is the operator's own setting, so it only has to tell two
#: honest paths apart.
_PATH_DIGEST_HEX = 8


def reload_alert_subject(path: str | os.PathLike[str], node: str | None = None) -> str:
    """The alert subject for one CRL file on one engine process:
    ``crl_reload:<path>@<node>``, or ``crl_reload:<path>`` for a lone engine (``node`` None).

    ``<path>`` is the file's path key (:func:`~messagefoundry.config.loaded_crls.crl_path_key`):
    absolute, and case-folded on Windows, so an alert and its clear name the same instance
    however the path was spelled. A path longer than :data:`ALERT_PATH_MAX_LENGTH` becomes
    ``~<checksum>~`` and its tail, which holds the file name. One subject per process, because
    each engine shard and each cluster node holds its own TLS contexts, so one process applying
    the file must not resolve another's alert. ``node`` is
    :attr:`~messagefoundry.pipeline.engine.Engine.instance_identity`.

    The colon keeps the subject outside the connection-name grammar, so no rule's default
    control target can read it as a connection."""
    key = crl_path_key(path)
    if len(key) > ALERT_PATH_MAX_LENGTH:
        # binascii, not zlib, as in process_alert_subject. backslashreplace, so a path with a
        # lone surrogate still gets a checksum instead of raising.
        digest = binascii.crc32(key.encode("utf-8", "backslashreplace"))
        tail = key[-(ALERT_PATH_MAX_LENGTH - _PATH_DIGEST_HEX - len("~~")) :]
        key = f"~{digest:0{_PATH_DIGEST_HEX}x}~{tail}"
    return process_alert_subject(f"crl_reload:{key}", node)


@dataclass(frozen=True)
class ReloadOutcome:
    """What one pass did for one CRL file that a running context held an older copy of."""

    path: str
    #: Contexts now checking against the file.
    reloaded: int
    #: Why some or all of the stale contexts kept their old copy, or ``None`` when none did.
    refusal: ReloadRefusal | None
    #: Contexts still on the copy they held when this pass ended. 0 when ``refusal`` is ``None``.
    stale: int = 0
    #: True when the remedy names a restart and a start would refuse the file too, until one of
    #: its CRLs takes effect. The reason says so with the time; an alert carries only this flag.
    start_refuses: bool = False

    @property
    def remedy_class(self) -> str | None:
        """The short token for what the operator does next (:data:`_REMEDY_CLASS`), or ``None``
        when nothing was refused."""
        return None if self.refusal is None else _remedy_class(self.refusal.remedy)


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
    reason = f"its CRL from issuer {issuer!r} is not in effect until {log_timestamp(takes_effect)}"
    lapsing = _first_lapse(held)
    if lapsing is not None and lapsing.next_update < takes_effect:
        return (
            f"{reason}, and the hop's CRL from issuer {lapsing.issuer!r} lapses earlier, at "
            f"{log_timestamp(lapsing.next_update)}"
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
            f"the running hop holds (thisUpdate {log_timestamp(old.this_update)}, nextUpdate "
            f"{log_timestamp(old.next_update)}). A superseding CRL must have a later thisUpdate, a "
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


def _certificates_in(copy: Path, blocks: Sequence[CrlBlock], *, label: str) -> set[bytes]:
    """The DER of each certificate in the CRL file at ``copy``, read on a scratch context.

    A load into the live context cannot be undone, so this is where a planted certificate is found
    (BACKLOG #1890), and where the CRLs OpenSSL loads are proved to be exactly the judged ``blocks``
    (:func:`~messagefoundry.config.tls_policy.crl_scratch_context`). Without that proof a block
    OpenSSL skips would be recorded as applied while the context kept checking the old CRL. A
    non-CA certificate refuses: the live store's own list (``get_ca_certs``) holds only CA
    certificates, so one could never be proved already trusted. Raises ``ValueError``."""
    scratch = crl_scratch_context(str(copy), blocks, label=label)
    stats = scratch.cert_store_stats()
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
    among equals), kept whole, and whether the next pass must judge the same bytes again."""

    def __init__(self) -> None:
        self.strongest: tuple[str, str] | None = None
        #: True once the next pass must judge these bytes again. Either a refusal that can lift
        #: (:data:`_RETRIED`) is what stopped a context or the whole pass, so that context may
        #: still take them, or the reason reported carries a warning that ends with time.
        self.pending = False
        #: An unexpected failure, logged with its traceback once per file version.
        self.error: BaseException | None = None
        #: True when the refusal reported names a restart and a start would refuse the file too,
        #: until one of its CRLs takes effect (:attr:`ReloadOutcome.start_refuses`).
        self.start_refuses = False

    def add(self, reason: str, remedy: str, *, stops: bool = True) -> None:
        """Record one refusal. Pass ``stops=False`` where a check further on may still be what
        stops the context. The refusal then counts for the rank alone, and :meth:`stopped_by`
        says so if it turns out to be what holds the context back."""
        if self.strongest is None or _RANK[remedy] < _RANK[self.strongest[1]]:
            self.strongest = (reason, remedy)
        if stops:
            self.stopped_by(remedy)

    def stopped_by(self, remedy: str) -> None:
        """Note that the refusal naming ``remedy`` is what holds a context, or the pass, back."""
        self.pending = self.pending or remedy in _RETRIED

    def reopen(self) -> None:
        """Have the next pass judge these bytes again, whatever stopped each context."""
        self.pending = True

    @property
    def sticky(self) -> bool:
        """Whether the reload treats this pass's verdict as final until the file changes.

        False while a refusal that can lift is what stops some context. Once it lifts, that
        context takes the file, or meets a check it had not reached, which may outrank the
        refusal reported. False while the refusal reported can itself lift, because the operator
        would go on reading it afterwards. A refusal that can lift but is neither changes nothing
        when it does: a check that does not lift stops its context all the same, and a refusal
        that outranks it is the one reported (vault BACKLOG #2866).

        "Final" is the reload's rule, not a proof. A file check reads the hop's CA list, which a
        CA directory can still add to. A file to fix was already final on its own, and a wait
        beside it no longer keeps the pass open."""
        return not self.pending and (self.strongest is None or self.strongest[1] not in _RETRIED)


# Pass state, touched only under _PASS_LOCK. Keyed by path key, pruned to the held paths each pass.
_PASS_LOCK = threading.Lock()
#: The (size, mtime_ns, file id) last seen for each held file, and the fingerprint of its bytes then.
_SEEN: dict[str, tuple[tuple[int, int, int], tuple[int, int]]] = {}
#: Held files that could not be read, so the warning is logged once until one can be read again.
_UNREADABLE: set[str] = set()
#: The last unexpected failure per file outside a judged version, so its traceback is logged once.
_FAILED: dict[str, str] = {}
#: The fingerprint of each held file's bytes when a pass last judged them, and the label it gave
#: them, so every retry of one refusal names the file the same way (:func:`_label`).
_LABELS: dict[str, tuple[tuple[int, int], str]] = {}


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
    #: True when these bytes were refused before, and not for good (:attr:`_Refusals.sticky`).
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
        # The reload treats this verdict as final until the file changes, so these bytes are not
        # judged again. :attr:`_Refusals.sticky` says which verdicts are retried every pass.
        return prior
    return _Change(pem, fingerprint, retry=prior is not None)


def _label(
    key: str,
    fingerprint: tuple[int, int],
    stale: Sequence[tuple[ssl.SSLContext, HeldCrl]],
    path: str,
    *,
    refused: bool,
) -> str:
    """How a pass names the file whose bytes have ``fingerprint``: the label those bytes were
    first refused under, worked out from the holders that were ``stale`` then.

    Every reason leads with the label, and :func:`_finish` logs a refusal again when its reason
    changes. A label worked out afresh each pass changed for the same bytes. The stale set shrinks
    as contexts take the file, so the path became one holder's setting once the others were
    current. Reading every holder instead would not hold still either: a short-lived context
    built from the file as it is now comes and goes between passes. So the label is worked out
    when the bytes are first refused, and kept while that refusal stands (vault BACKLOG #3099).

    ``refused`` says a refusal for these bytes is on record. Without one the label is worked out
    afresh: bytes put back after a change may meet different holders, and must not be named by
    the ones that were stale the first time."""
    kept = _LABELS.get(key)
    if refused and kept is not None and kept[0] == fingerprint:
        return kept[1]
    shown = next((h.configured_path for _, h in stale if h.configured_path), path)
    # The setting, only when every stale holder recorded the same one. Several listeners can share
    # one CRL now that each records its connection's tls_crl_file (vault BACKLOG #1997), and naming
    # whichever the pass met first sent the operator to one hop of several. The path alone is
    # never wrong, and it does not grow with the number of holders.
    held_by = {h.setting for _, h in stale}
    label = crl_label(shown, held_by.pop() if len(held_by) == 1 else None)
    _LABELS[key] = (fingerprint, label)
    return label


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
    label = _label(key, fingerprint, stale, path, refused=prior is not None)
    refusals = _Refusals()
    reloaded = 0
    blocks: tuple[CrlBlock, ...] = ()  # stays empty when the bytes cannot be judged
    try:
        # A CRL not in effect yet is judged here, not refused there: a context at the cap, a held
        # CRL nothing supersedes, or a file to fix each outranks a wait, and must be reported.
        facts, blocks = judge_crl_bytes(pem, label=label, now=now, require_in_effect=False)
        verdicts: dict[tuple[CrlBlock, ...], tuple[str, str] | None] = {}
        timing: dict[tuple[CrlBlock, ...], tuple[str, str] | None] = {}
        # Every stale context, with the verdict that holds it back, if any. Each still gets the
        # per-context file checks below, since a file a start would refuse, or would load and then
        # fail every handshake on, outranks a restart or a wait.
        ready: list[tuple[ssl.SSLContext, HeldCrl, tuple[str, str] | None]] = []
        for ctx, held in stale:
            # First, for every context: does some CRL it holds lapse before the file can apply?
            # That outranks every other verdict below, so no other path may hide it. It is recorded
            # for the rank alone: what stops this context is decided below and in ``_load``.
            if held.blocks not in timing:
                timing[held.blocks] = _time_verdict(held.blocks, blocks, now=now)
            if (late := timing[held.blocks]) is not None and late[1] == LAPSES_FIRST:
                refusals.add(f"{label}: {late[0]}", LAPSES_FIRST, stops=False)
            if held.reloads >= max_reloads:
                capped = (
                    f"this hop has taken {held.reloads} CRL reloads, and each one stays in its "
                    "trust store ([cert_monitor].crl_max_reloads)"
                )
                ready.append((ctx, held, (capped, RESTART)))
                continue
            if held.blocks not in verdicts:
                verdicts[held.blocks] = supersede_refusal(held.blocks, blocks, now=now)
            ready.append((ctx, held, verdicts[held.blocks]))
        with staged_crl(pem) as copy:
            # OpenSSL's own reading of the file first: a file a start would refuse is a file to
            # fix, which outranks every verdict above.
            certificates = _certificates_in(copy, blocks, label=label)
            reloaded = _load(
                pem, copy, certificates, label, ready, refusals, fingerprint, facts, blocks
            )
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
            f"{why}. Not before {log_timestamp(unmet.this_update)}: a start until then refuses this "
            f"file too, since its CRL from issuer {unmet.issuer!r} is not in effect",
            remedy,
        )
        # Judged again each pass, so the warning goes once its time has passed.
        refusals.reopen()
        # The reopen above is also what lets the flag live on the outcome and not on the recorded
        # refusal: such a refusal is never final, so ``_pending`` never replays it without the flag.
        refusals.start_refuses = True
    return _finish(label, path, fingerprint, stale, reloaded, refusals, prior)


def _load(
    pem: bytes,
    copy: Path,
    certificates: set[bytes],
    label: str,
    ready: list[tuple[ssl.SSLContext, HeldCrl, tuple[str, str] | None]],
    refusals: _Refusals,
    fingerprint: tuple[int, int],
    facts: CrlFacts,
    blocks: tuple[CrlBlock, ...],
) -> int:
    """Load the staged ``copy`` into each context in ``ready`` that passes the per-context checks.

    A context paired with a verdict (a wait, a restart) gets the checks and then that verdict, so a
    file to fix is reported as one whatever else holds the context back. Returns how many contexts
    now hold the file. A failure in one context is that context's refusal alone, retried next pass:
    the contexts already loaded stay counted, and the rest are still tried.

    The check that stops a context decides whether these bytes are judged again
    (:attr:`_Refusals.sticky`). A context that fails a file check is stopped by it, wait or no
    wait. A context that passes every file check and only waits takes them once the wait lifts."""
    reloaded = 0
    signatures: dict[frozenset[bytes], tuple[str, bool] | None] = {}
    for ctx, held, held_back in ready:
        if held_back is not None:
            # :data:`_RANK` picks the refusal reported, whatever the order: order only breaks a
            # tie. The place of this call still matters. Each file check below ends in
            # ``continue``, so a verdict recorded after them would be skipped for a context that
            # fails one. Recorded for the rank alone, until the file checks have passed.
            refusals.add(f"{label}: {held_back[0]}", held_back[1], stops=False)
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
            if held_back is not None:
                # Every file check passed, so this verdict alone holds the context back.
                refusals.stopped_by(held_back[1])
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
    kept = len(stale) - reloaded
    if prior is None or prior.reason != reason:
        # Once per file version: a retried pass repeats every minute, and the monitor carries it.
        # The runner raises ``crl_reload_refused`` by the same rule, from the outcome returned
        # here. Not from this function: it runs in a worker thread, and a notifier's alert-state
        # write needs the event loop.
        log.error(
            "crl_reload: refused to apply the replaced CRL file to %d running TLS context(s), "
            "which keep the copy they hold: %s. %s",
            kept,
            reason,
            remedy,
            exc_info=refusals.error,
        )
    return ReloadOutcome(path, reloaded, refusal, kept, refusals.start_refuses)


def _held_by_path() -> dict[str, list[tuple[ssl.SSLContext, HeldCrl]]]:
    """Every held CRL file this pass may reload, with the contexts holding it.

    A copy from a CA bundle is left out (vault BACKLOG #2319). The rules here are a CRL setting's:
    a CA file that gained a CA would be refused as a file to fix and told to hold a bare CRL, when
    the CA file is right and a restart applies it. The expiry monitor still judges that copy and
    names a restart as the remedy."""
    by_path: dict[str, list[tuple[ssl.SSLContext, HeldCrl]]] = {}
    for ctx, held in held_contexts():
        if held.ca_bundle:
            continue
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
            # A verdict the reload treats as final is not judged again, so the count is taken
            # here: the contexts that do not hold the refused bytes.
            kept = sum(held.fingerprint != verdict.fingerprint for _, held in pairs)
            refused.append(ReloadOutcome(_read_path(pairs), 0, verdict, kept))
        elif verdict is not None:
            pending[key] = verdict
    return pending, refused


def _prune(held: Collection[str]) -> None:
    """Drop the pass state and the refusals of every path key not in ``held``. Under the pass lock."""
    for state in (_SEEN, _FAILED, _LABELS):
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


class _Alerted(NamedTuple):
    """A refusal :class:`CrlReloadRunner` has raised ``crl_reload_refused`` for and not resolved."""

    #: The file as the pass read it, for the clear's log line and payload.
    path: str
    #: The refused bytes and the reason: together, the file version the alert was raised for.
    fingerprint: tuple[int, int]
    reason: str


class CrlReloadRunner:
    """Runs :func:`reload_replaced_crls` every ``interval_seconds``, off the event loop.

    Engine-owned like the expiry monitor, but not gated on ``[cert_monitor]``: turning the alert off
    must not also stop revocations reaching a running hop. Not leader-gated: each process holds its
    own contexts.

    **It raises ``crl_reload_refused`` for a refused file (vault BACKLOG #2904).** Once per file
    version, by the rule the pass logs its ERROR by: again only when the file's bytes change or
    the refusal's reason does. The pass runs in a worker thread, so the alert is raised here,
    on the event loop, from the outcomes the pass returns. ``alert_sink`` defaults to a
    :class:`~messagefoundry.pipeline.alerts.LoggingAlertSink`, as the expiry monitor's does.
    ``node`` names this process in the alert subject (:func:`reload_alert_subject`).

    **It resolves that alert with ``crl_reload_applied``, and only on evidence.** A pass returns
    no outcome for a file it could not read, and none when it failed, while the refusal still
    stands. So a missing outcome clears nothing: the alert is resolved only once the refusal is
    gone from the record (:func:`~messagefoundry.config.loaded_crls.reload_refusals`). That is
    when the file was applied, when it was put back to the bytes the hops hold, and when no hop
    holds it any more. :meth:`stop` resolves what is still open, because a restart rebuilds
    every context from the file and nothing later would clear it. A process that dies without
    stopping leaves its alerts open, for an operator to resolve in the alert list."""

    def __init__(
        self,
        *,
        interval_seconds: float = RELOAD_INTERVAL_SECONDS,
        max_reloads: int = MAX_RELOADS,
        reload: Callable[[], object] | None = None,
        stop_timeout_seconds: float = STOP_TIMEOUT_SECONDS,
        skip_when_idle: bool = True,
        alert_sink: AlertSink | None = None,
        node: str | None = None,
    ) -> None:
        self._interval = interval_seconds
        self._reload = reload or functools.partial(reload_replaced_crls, max_reloads=max_reloads)
        # With no CRL load recorded there is nothing to reload, so no worker thread is started.
        self._skip_when_idle = skip_when_idle
        self._stop_timeout = stop_timeout_seconds
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self._alert_sink: AlertSink = alert_sink or LoggingAlertSink()
        self._node = node
        # Per path key, the refusal already alerted. A pass returns a refused outcome every
        # minute, so this is what keeps the alert to one per file version. It is also the set of
        # alerts this runner has open. Touched only on the event loop.
        self._alerted: dict[str, _Alerted] = {}
        # The sink calls now failing, as (what, path key): one WARNING per failing streak of each,
        # not one a pass.
        self._sink_failing: set[tuple[str, str]] = set()

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
        pass lock keeps it from overlapping a runner started next.

        Every ``crl_reload_refused`` alert this runner still has open is resolved on the way out.
        A stopped runner can no longer see a refusal clear, and the next start builds every
        context from the file as it is then, so an alert left open would say hops hold an old
        copy when none does. A runner started again raises it afresh if a refusal still stands."""
        self._stop.set()
        task = self._task
        self._task = None
        if task is not None:
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
        # Also with no task: a clear the sink refused at an earlier stop is retried by this one.
        self._resolve(list(self._alerted), "the reload has stopped")

    async def _run(self) -> None:
        # Sleep first: every context was just built from the file as it is now.
        while not self._stop.is_set():
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._stop.wait(), self._interval)
            if self._stop.is_set():
                return
            if self._skip_when_idle and not has_held_copies():
                _forget_all()
                # No pass runs, so nothing else would resolve an alert for a file no hop holds
                # now. Read from the record all the same: _forget_all skips a held pass lock.
                self._resolve_cleared()
                continue
            outcomes: object = None
            try:
                outcomes = await asyncio.to_thread(self._reload)
            except Exception:
                log.exception("crl_reload pass failed; will retry next interval")
            if self._stop.is_set():
                # stop() resolves what is open. A refusal raised now would page, and the stop
                # would resolve it a moment later, for a condition the restart itself ends.
                return
            # After the await, so on the event loop: a notifier schedules its alert-state write
            # with the running loop, and off the loop that write is dropped without an error.
            try:
                self._report(outcomes)
            except Exception:
                # Broad on purpose, as for the pass: reporting must never end the loop that
                # applies revocations. An injected ``reload`` can return an outcome of any shape.
                log.exception("crl_reload: reporting a pass failed; will retry next interval")

    def _report(self, outcomes: object) -> None:
        """Raise ``crl_reload_refused`` for each refusal in ``outcomes`` not alerted yet, then
        resolve the alerts whose refusal no longer stands.

        ``outcomes`` is whatever the pass returned. An injected ``reload`` may return anything,
        and a pass that raised returns nothing, so only a list of :class:`ReloadOutcome` is read."""
        for outcome in outcomes if isinstance(outcomes, list) else ():
            if isinstance(outcome, ReloadOutcome) and outcome.refusal is not None:
                self._raise_refused(outcome, outcome.refusal)
        self._resolve_cleared()

    def _resolve_cleared(self) -> None:
        """Resolve every open alert whose refusal the record no longer holds.

        The record, never the outcomes: a file the pass could not read and a pass that failed
        both return no outcome while the refusal stands. The pass clears the record when every
        context holds the file's bytes, and drops it when no hop holds the file. Forgetting the
        alert here is also what makes the same bytes, refused again later, alert again, as they
        log again."""
        if not self._alerted and not self._sink_failing:
            return
        standing = reload_refusals()
        # A raise that kept failing for a refusal since cleared is moot. End its streak, so the
        # next failure for that file is logged again.
        self._sink_failing = {
            (what, key) for what, key in self._sink_failing if what != "raised" or key in standing
        }
        self._resolve(
            [key for key in self._alerted if key not in standing], "the refusal no longer stands"
        )

    def _resolve(self, keys: Sequence[str], why: str) -> None:
        """Raise ``crl_reload_applied`` for each alert in ``keys``, and forget the ones raised."""
        for key in keys:
            path = self._alerted[key].path
            try:
                self._alert_sink.crl_reload_applied(
                    reload_alert_subject(key, self._node), path=path
                )
            except Exception:
                # Broad on purpose, as in _raise_refused. Kept as open, so the next pass or the
                # stop retries the clear.
                self._sink_failed("resolved", key)
                continue
            self._sink_failing.discard(("resolved", key))
            del self._alerted[key]
            log.info("crl_reload: the refused-reload alert for %s is resolved: %s", path, why)

    def _sink_failed(self, what: str, key: str) -> None:
        """One WARNING per failing streak of one call for one file, from inside the ``except``
        that caught the failure. Per call and per file, so one file's success does not restart
        another's streak, and one standing failure does not hide a new one."""
        if (what, key) not in self._sink_failing:
            self._sink_failing.add((what, key))
            log.warning(
                "crl_reload: the refused-reload alert could not be %s; the next pass, or the "
                "stop, tries again",
                what,
                exc_info=True,
            )

    def _raise_refused(self, outcome: ReloadOutcome, refusal: ReloadRefusal) -> None:
        key = crl_path_key(outcome.path)
        version = (refusal.fingerprint, refusal.reason)
        known = self._alerted.get(key)
        if known is not None and (known.fingerprint, known.reason) == version:
            return  # this version of the file is alerted already
        token = _remedy_class(refusal.remedy)
        try:
            self._alert_sink.crl_reload_refused(
                reload_alert_subject(key, self._node),
                path=outcome.path,
                remedy_class=token,
                stale_contexts=outcome.stale,
                # Only a sentence the class map vouches for. Never ``refusal.reason``.
                remedy=refusal.remedy if token != _OTHER_REMEDY_CLASS else "",
                start_refuses=outcome.start_refuses,
            )
        except Exception:
            # Broad on purpose: a sink must never raise, and a broken one must not end the loop
            # that applies revocations. Not recorded as alerted, so the next pass retries it.
            self._sink_failed("raised", key)
            return
        self._sink_failing.discard(("raised", key))
        self._alerted[key] = _Alerted(outcome.path, *version)
