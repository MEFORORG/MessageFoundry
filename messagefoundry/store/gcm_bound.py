# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The PERSISTED per-key AES-GCM invocation bound (ASVS 11.3.4) — backend-agnostic half.

Nonce *generation* was never the gap: every encrypt draws a fresh 96-bit ``os.urandom`` nonce, which is
the NIST SP 800-38D-appropriate scheme. The gap was the **bound**. ``AesGcmCipher`` carried a purely
in-memory counter that reset on every process start, so across a deployment's lifetime the 2**32 ceiling
was unreachable, the 2**31 warning never fired, and "rotate before the birthday bound" was a calendar
hope rather than an enforced control.

**The scheme.** One ``cipher_meta`` row per ``key_id`` (identical DDL shape on all three backends) holds
a cumulative reserved total. A process RESERVES a block of invocations — one atomic ``+=`` returning the
new total — and only then spends them. Three properties fall out:

* **An unclean exit can only OVER-count.** The reservation is durable *before* the encrypts happen, so a
  hard kill forfeits at most the unspent remainder of a block — bounded slack in the conservative
  direction. A CLEAN close settles the exact figure instead (charging an overspend, refunding an unspent
  reserve), because forfeiting a whole block per open does not survive arithmetic: ~65k opens would
  exhaust a key on paper alone, and a crash-looping service under NSSM auto-restart would reach the
  fail-closed ceiling in about a week with no cryptographic cause.
* **The reserve is topped up on DEMAND, not on a timer.** Crossing the half-block watermark fires the
  cipher's refill hook (:meth:`AesGcmCipher.set_refill_hook`) so the engine runner refills immediately;
  its poll interval is only a floor. A timer alone silently loses the "reserve leads spend" property
  above ``block / interval`` encrypts per second.
* **Multi-process aggregation is free.** The atomic add is the aggregation. Engine shards
  (``serve --shard``) and ``[cluster]`` HA nodes all sit on the ONE unified store — >1 shard already
  *requires* a server DB — so every process charges the same row. An offline ``rotate-key``, which
  performs the single largest encrypt burst in the product, charges it too.
* **The hot path pays one DB write per ~2**15 encrypts**, not one per encrypt. Anything finer would
  land on the pipeline's serial commit chain as a throughput regression.

**Which key a row counts (ADR 0196).** ``key_id`` is the one-way SHA-256 fingerprint of the AES key new
values are actually sealed under -- :attr:`AesGcmCipher.invocation_key_id`. For the cell-bound writer
that is the store's data sub-key, ``HKDF(DEK, info = label || store salt)``, not the DEK. The row lives in
the store it protects, and when it was keyed on the DEK, a store recreated or rewound under the same DEK
met no row and counted a used key from zero with no signal. A sub-key cannot be reused that way: a new
store mints a new salt, and ``restore`` gives the store it writes a new one, so the key is new by
construction and a count of zero is its TRUE count. The frozen v1 writer has no salt field and stays
keyed on the DEK, so ``[store].aad_bind = false`` keeps the old exposure (ADR 0196). The stored row id
is that fingerprint tagged with the scheme that made it, :func:`~messagefoundry.store.crypto.cipher_meta_key`
(BACKLOG #3421); a row keyed on the bare fingerprint, written before tags, is folded into it.

**Rotation semantics.** A NEW DEK derives new sub-keys, so it has no row and starts at zero -- no reset
operation is needed, and none is offered. Zeroing an EXISTING key_id's row is deliberately *not*
implemented: it would let an operator refresh the birthday budget of a key they never actually changed,
defeating the whole control. Re-supplying a retired DEK to the same store resolves to its existing
sub-key row and inherits its accumulated count. What the engine cannot see is a store file copied or
rolled back outside it -- a VM snapshot, a DBA restore of a server database, a staging copy given the
production key: that copy carries its salt and its row. ADR 0196 records it as an accepted limit.

**Out of scope: the ``vault_transit`` store cipher.** It draws no local nonce and builds no local
``AESGCM``. :func:`bounded_cipher` returns ``None`` for it and for the identity cipher, and every
entry point here degrades to a no-op. So nothing counts, alarms or refuses on the store cipher's
path. Its bound is a DOCUMENTED OPERATOR PRECONDITION, not a counted one: the operator must rotate
the Transit data key before any one key version seals 2**32 values, and the engine does not check
that they do. It is weaker than this
module's bound, and the owner ruled on 2026-09-28 that it does not meet ASVS 11.5.2 ruling R3, which
needs an engine-recorded attestation. ADR 0138's 2026-09-28 amendment states the precondition and why
(BACKLOG #1173). That attestation is :mod:`messagefoundry.store.transit_attestation` (BACKLOG #2337,
ADR 0138's 2026-10-07 amendment): a CLI-written, audited store row naming the Transit key, without which
``serve`` refuses under enforce. It records who vouched for the rotation; it still counts nothing.

**DR archives under ``vault_transit`` DO draw local nonces** whenever a key resolves for the backup.
``pipeline/dr_backup.py`` then seals them under that DEK in process and charges the DEK's own
``cipher_meta`` row. Nothing enforces that row's ceiling in this mode. ADR 0196's 2026-10-10
amendment traces the path by symbol (BACKLOG #2187; a seat decision under owner delegation
2026-10-08, not an owner ruling).
"""

from __future__ import annotations

import asyncio
import logging
import threading
import weakref
from collections.abc import Awaitable, Callable

from messagefoundry.store.crypto import (
    _GCM_RESERVE_BLOCK,
    AesGcmCipher,
    Cipher,
    new_store_salt,
    parse_store_salt,
)

__all__ = [
    "GCM_RESERVE_BLOCK",
    "INVOCATION_BOUND_NOTE",
    "bind_store_salt",
    "bounded_cipher",
    "checkpoint_invocations",
    "counts_under_dek",
    "idle_checkpoint_total",
    "reserve_invocations_ahead",
]

log = logging.getLogger(__name__)

#: Public alias of the reserve block size (tests + the runner read it; the cipher owns the value).
GCM_RESERVE_BLOCK = _GCM_RESERVE_BLOCK

#: The note a failed add carries when a pass re-raises it (:func:`_account`): a store open's strict
#: pass, or any pass before the cipher has read its row. A CLI open arm tests for it to report the
#: failure as "could not start", as it reports a key refusal, rather than as a late store error.
INVOCATION_BOUND_NOTE = "raised while the AES-GCM invocation bound read its persisted total"

#: ``(key_id, count) -> new cumulative total``. Each backend supplies its own atomic upsert-add. ``count``
#: is normally positive (a reservation); a settlement may pass a NEGATIVE count to refund an unspent
#: reserve, which every backend's ``invocations = invocations + ?`` upsert handles unchanged.
AddInvocations = Callable[[str, int], Awaitable[int]]

#: ``(candidate_salt_hex) -> the store's salt hex``. Each backend supplies an atomic insert-if-absent of
#: the candidate into its one-row ``store_salt`` table, then reads the row back, so concurrent first
#: opens of one empty server database settle on ONE salt (ADR 0196 AC-2).
EnsureSalt = Callable[[str], Awaitable[str]]


def bounded_cipher(cipher: Cipher | None) -> AesGcmCipher | None:
    """The cipher whose invocations the store must account for, or ``None``.

    Of the store ciphers, only the in-process AES-GCM keyring draws local nonces under a local key, so
    only it has a birthday budget this store can bound. The identity cipher encrypts nothing;
    ``TransitCipher`` encrypts inside the vault, and its bound is the operator's rotation of the
    Transit key, which nothing here counts (the module docstring's ``vault_transit`` paragraphs)."""
    return cipher if isinstance(cipher, AesGcmCipher) else None


def counts_under_dek(cipher: Cipher | None) -> bool:
    """Whether ``cipher`` seals under the DEK itself, so its count is the DEK's and recreating the store
    under the same DEK resets it: the frozen v1 writer (ADR 0196). False for the cell-bound writer,
    whose count belongs to a store data sub-key, and for a cipher with no local key."""
    bound = bounded_cipher(cipher)
    return bound is not None and bound.store_salt is None


#: One ``asyncio.Lock`` per bounded cipher and event loop (BACKLOG #5608). Every accounting pass on
#: one cipher reads its state, awaits the persisted add, and applies the grant. Two passes interleaved
#: there would compute their counts from the same state and could apply the grants out of the
#: database's order. A settlement refund replaces the cipher's total with the one its add returned, so
#: a refund granted after a later refill would leave the cipher's figure below the persisted one by a
#: whole block: an under-count, the one direction this bound may never drift. One lock per loop,
#: because an ``asyncio.Lock`` is bound to the loop it first waits on. Both maps are weak, so a closed
#: store's key material is never kept alive; a lock that was ever contended does hold its loop, until
#: the cipher goes. The guard serializes the map itself, since a cipher may be shared with code
#: running in a worker thread. RESIDUAL: passes on two different loops are not serialized against
#: each other; nothing in the engine runs one cipher's passes on two loops at once.
_PASS_LOCKS: weakref.WeakKeyDictionary[
    AesGcmCipher, weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Lock]
] = weakref.WeakKeyDictionary()
_PASS_LOCKS_GUARD = threading.Lock()


def _pass_lock(bound: AesGcmCipher) -> asyncio.Lock:
    loop = asyncio.get_running_loop()
    with _PASS_LOCKS_GUARD:
        per_loop = _PASS_LOCKS.get(bound)
        if per_loop is None:
            per_loop = _PASS_LOCKS[bound] = weakref.WeakKeyDictionary()
        lock = per_loop.get(loop)
        if lock is None:
            lock = per_loop[loop] = asyncio.Lock()
        return lock


def _pass_need(bound: AesGcmCipher, *, settle: bool) -> int:
    """What a checkpoint pass would charge: the exact settlement, or the reserve's shortfall."""
    return bound.invocation_settlement() if settle else bound.invocation_reserve_shortfall()


def idle_checkpoint_total(cipher: Cipher | None, *, settle: bool = False) -> int | None:
    """The cumulative total when a checkpoint pass would have nothing to do, else ``None``.

    A lock-free read for a backend that would otherwise take a lock only to find the pass idle. Only a
    hydrated cipher qualifies, so a first contact always runs a full pass. A stale read only defers
    work to the next pass."""
    bound = bounded_cipher(cipher)
    if bound is None or not bound.invocation_bound_hydrated:
        return None
    if _pass_need(bound, settle=settle):
        return None
    return bound.cumulative_invocations()


async def _add_then_grant(
    bound: AesGcmCipher, add: AddInvocations, need: int, *, floor: int | None = None
) -> None:
    """Run the persisted add and the in-memory grant as one unit a caller's cancellation cannot split.

    The add runs in its own task, which nothing here cancels, so a cancellation of the caller cannot
    abandon a write the database may still commit (an aiosqlite statement runs on a worker thread
    whatever happens to the awaiting coroutine). A cancellation that lands mid-add is held until the
    add finishes and its grant is applied, then re-raised. Without that, a committed REFUND with no
    grant would leave the cipher spending a reserve the store no longer holds. Holding the
    cancellation also keeps the caller's locks, this pass's and a SQLite store's writer lock, held
    until the add is done with the connection.

    THE COST: a cancelled pass returns only once its add does, so a stop waits out the backend's own
    statement and acquire timeouts while the database is unreachable. THE RESIDUAL: a cancellation
    of the add task ITSELF, which only a shutdown that cancels every task delivers, can still split
    the pair; a split reservation over-counts, and a split refund is the final settlement of a
    process that encrypts nothing after it.

    ``floor`` is the cipher's figure before a strict pass: the grant's total is raised to at least
    ``floor + need``, so reading a row another handle never charged cannot lower the figure."""
    task = asyncio.ensure_future(add(bound.invocation_key_id, need))
    cancelled = False
    while not task.done():
        try:
            # `wait`, not `shield`: it never cancels the task, and a failure the task raises after
            # this caller was cancelled is still read below rather than logged by the loop
            # (BACKLOG #2087).
            await asyncio.wait((task,))
        except asyncio.CancelledError:
            cancelled = True
    if task.cancelled():
        raise asyncio.CancelledError  # the add itself was cancelled, so it returned no total
    try:
        total = task.result()
    except Exception as exc:
        if cancelled:
            # The cancellation wins, but the failure is recorded rather than dropped.
            _log_by_class(
                exc, "the AES-GCM invocation bound's add failed after its pass was cancelled (%s)"
            )
            raise asyncio.CancelledError from exc
        raise
    if floor is not None:
        total = max(total, floor + need)
    bound.grant_invocations(need, total)
    if cancelled:
        raise asyncio.CancelledError


def _log_by_class(exc: BaseException, message: str, *args: object) -> None:
    """``message`` at WARNING with ``exc``'s class as its last argument, the traceback at DEBUG
    only: a driver's message may carry a path or a value (CLAUDE.md section 9, BACKLOG #5720)."""
    log.warning(message, *args, type(exc).__name__)
    log.debug("the invocation bound's add failure", exc_info=exc)


async def _account(
    bound: AesGcmCipher,
    add: AddInvocations,
    need: int,
    what: str,
    *,
    strict: bool = False,
    floor: int | None = None,
) -> None:
    """Charge ``need`` to the key's persisted total and grant it to the cipher.

    Fail-closed on the FIRST hydration (BACKLOG #5608). Until one add has returned the key's persisted
    total, the cipher's figure is only this process's own spend, so a key another process or an
    earlier run had already taken to the ceiling would keep encrypting. That failure is re-raised
    instead of being logged, and the cipher refuses to encrypt until a later pass hydrates it.
    ``strict`` re-raises too on a cipher hydrated before, so the store open that passes it fails:
    the cipher's figure may come from another store handle and only this store's row is the key's
    total here. That cipher stays hydrated, so it is not refused; the open is. Otherwise a failed add
    on a hydrated cipher is logged and retried: its figure then carries the key's lifetime total, so
    the ceiling still holds against it.

    The failure is re-raised AS ITSELF. A store that is locked, busy or unreachable raises its
    driver's error, and a caller that reads :class:`~messagefoundry.store.crypto.CipherError` as a
    key refusal must not send an operator to the key for it; a ``CipherError`` stays one. It
    carries :data:`INVOCATION_BOUND_NOTE`, once, since an add may raise one stored exception on
    every retry; a caller tests for the note to tell this failure from any other at the open."""
    try:
        await _add_then_grant(bound, add, need, floor=floor)
    except Exception as exc:
        if strict or not bound.invocation_bound_hydrated:
            if INVOCATION_BOUND_NOTE not in getattr(exc, "__notes__", ()):
                exc.add_note(INVOCATION_BOUND_NOTE)
            raise
        _log_by_class(
            exc,
            "could not reach the AES-GCM invocation bound for the active key while %s (%s); the "
            "in-process ceiling still applies and the next pass retries",
            what,
        )


async def checkpoint_invocations(
    cipher: Cipher | None, add: AddInvocations, *, settle: bool = False, strict: bool = False
) -> int | None:
    """Reconcile the live cipher's spend against its persisted reserve; return the cumulative total.

    ``settle=False`` (the periodic checkpoint) tops the reserve back up to a whole block once it falls
    below half, keeping the persisted total AHEAD of what has been spent.

    ``settle=True`` (store close, and the end of a long offline burst) squares the persisted total with
    what was ACTUALLY spent — charging an overspend, refunding an unspent reserve — and reserves nothing
    further. So ``rotate-key``'s millions of re-encrypts are accounted even where they outran the refill
    cadence, while a short-lived CLI process that encrypted a handful of values does not permanently burn
    a whole 2**16 block of the key's budget. Idempotent: a second settle finds nothing to correct.

    ``strict=True`` (a store open's first pass) raises on any failed add, so an open never proceeds on
    a figure another store handle left in the cipher (:func:`_account`).

    Returns ``None`` when the store's cipher carries no bound (identity / ``vault_transit``). Passes on
    one cipher run one at a time, and a caller's cancellation never splits an add from its grant
    (BACKLOG #5608). Once the cipher is hydrated, and unless ``strict``, this never raises: a
    checkpoint that cannot reach the DB is logged and retried next pass, since the in-process ceiling
    still holds meanwhile and a transient DB blip must not take the engine down. Before that, a failed
    add raises its own error (:func:`_account`)."""
    bound = bounded_cipher(cipher)
    if bound is None:
        return None
    async with _pass_lock(bound):
        if settle and not bound.invocation_bound_enabled:
            # Nothing was reserved, so nothing is owed; enabling here would leave a bound that has
            # read no row, and the cipher would refuse every later encrypt.
            return bound.cumulative_invocations()
        if not bound.invocation_bound_enabled:
            # First contact: switch the cipher onto the persisted bound so the very first block is
            # reserved before it is spent.
            bound.enable_invocation_bound()
        floor = None
        if strict:
            # Any reserve the cipher still holds was charged to the row another handle read, not to
            # this one, so it is forfeited: an over-count at worst. That also leaves a shortfall, so
            # a strict pass always reads this store's row.
            bound.forfeit_invocation_reserve()
            floor = bound.cumulative_invocations() if bound.invocation_bound_hydrated else None
        need = _pass_need(bound, settle=settle)
        # A settlement grant zeroes the reserve exactly (remaining was `-need`), so a repeated settle
        # is a no-op — in EITHER direction, an overspend charged or an unspent reserve refunded; a
        # refill grant hands over a fresh block.
        if need:
            what = "settling" if settle else "checkpointing"
            await _account(bound, add, need, what, strict=strict, floor=floor)
        return bound.cumulative_invocations()


async def reserve_invocations_ahead(cipher: Cipher | None, add: AddInvocations, count: int) -> None:
    """Reserve enough of the persisted bound to cover a burst of ``count`` encrypts BEFORE it starts.

    For a burst that cannot top the reserve up part-way. The at-open seal of one (table, column)
    surface runs as ONE transaction (BACKLOG #1169), so a crash leaves the surface all sealed or all
    unsealed. On SQLite a reservation commits the one writer connection, so reserving mid-surface would
    commit the surface half-sealed -- exactly the mixed state the refusal would then reject as
    tampering. Reserving the whole burst up front keeps the one invariant this bound rests on: the
    persisted total leads every encrypt, so an unclean exit can only OVER-count. A crash mid-surface
    forfeits the reservation for encrypts the rollback discarded, which is that same conservative bias.

    Same failure contract as :func:`checkpoint_invocations`: once the cipher is hydrated, a
    reservation that cannot reach the DB is logged and the burst proceeds under the in-process
    ceiling, which still applies; before that, it raises."""
    bound = bounded_cipher(cipher)
    if bound is None or count <= 0:
        return
    async with _pass_lock(bound):
        if not bound.invocation_bound_enabled:
            bound.enable_invocation_bound()
        need = bound.invocation_reserve_shortfall(ahead=count)
        if need:
            await _account(bound, add, need, "reserving ahead of an at-rest seal")


async def bind_store_salt(cipher: Cipher | None, ensure: EnsureSalt) -> None:
    """Bind the store's persisted salt into its cipher, minting it on a store that has none (ADR 0196).

    Runs at open, BEFORE the first checkpoint and before anything seals, so the first reserved block
    and the first value both land under this store's own sub-key. A store with no salt row is a new
    store or a restored one, and the salt minted here makes its data key new. No-op for the identity
    cipher and the ``vault_transit`` store cipher, which seal under no local key, and for the frozen v1
    writer, which has no salt field.

    Unlike the checkpoint, a failure here RAISES: the open cannot pick the key it seals under without
    it, and a guessed salt would split one store's values across keys no row accounts for."""
    bound = bounded_cipher(cipher)
    if bound is None or bound.store_salt is None:
        return
    salt_hex = await ensure(new_store_salt().hex())
    bound.bind_store_salt(parse_store_salt(salt_hex))
