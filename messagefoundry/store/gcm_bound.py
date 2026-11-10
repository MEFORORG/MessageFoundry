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

* **The reservation is durable *before* the encrypts happen** while the refill keeps up, so a hard kill
  then forfeits at most the unspent remainder of a block — bounded slack in the conservative
  direction. A CLEAN close settles the exact figure instead (charging an overspend, refunding an unspent
  reserve), because forfeiting a whole block per open does not survive arithmetic: ~65k opens would
  exhaust a key on paper alone, and a crash-looping service under NSSM auto-restart would reach the
  fail-closed ceiling in about a week with no cryptographic cause. The close takes its settlement
  through :func:`settle_at_close`, which closes the bound in the same step, so the cipher refuses every
  encrypt after it. A close whose store stays busy past its wait leaves an unspent reserve persisted,
  an over-count of at most a block, and waits for the store to charge an overspent one (BACKLOG
  #3191).
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
import contextlib
import logging
import weakref
from collections.abc import Awaitable, Callable, Iterator
from contextlib import AbstractAsyncContextManager, contextmanager

from messagefoundry.store.crypto import (
    _GCM_RESERVE_BLOCK,
    AesGcmCipher,
    Cipher,
    new_store_salt,
    parse_store_salt,
)

__all__ = [
    "GCM_RESERVE_BLOCK",
    "bind_store_salt",
    "bounded_cipher",
    "checkpoint_invocations",
    "counts_under_dek",
    "reopen_invocation_bound",
    "SETTLE_WAIT_SECONDS",
    "reserve_invocations_ahead",
    "settle_at_close",
]

log = logging.getLogger(__name__)

#: Public alias of the reserve block size (tests + the runner read it; the cipher owns the value).
GCM_RESERVE_BLOCK = _GCM_RESERVE_BLOCK

#: ``(key_id, count) -> new cumulative total``. Each backend supplies its own atomic upsert-add. ``count``
#: is normally positive (a reservation); a settlement may pass a NEGATIVE count to refund an unspent
#: reserve, which every backend's ``invocations = invocations + ?`` upsert handles unchanged.
AddInvocations = Callable[[str, int], Awaitable[int]]

#: ``(candidate_salt_hex) -> the store's salt hex``. Each backend supplies an atomic insert-if-absent of
#: the candidate into its one-row ``store_salt`` table, then reads the row back, so concurrent first
#: opens of one empty server database settle on ONE salt (ADR 0196 AC-2).
EnsureSalt = Callable[[str], Awaitable[str]]


class _InFlight:
    """The reservations and settlements under way on one cipher, so the close's final settlement
    can wait for them: one that lands after the close read the reserve would be a block, or a
    refund, the figure the close writes leaves out (BACKLOG #3191). Waiters are futures of the loop
    that waits, so no state here is bound to one event loop."""

    def __init__(self) -> None:
        self.count = 0
        self.waiters: list[asyncio.Future[None]] = []

    def leave(self) -> None:
        self.count -= 1
        if self.count == 0:
            waiters, self.waiters = self.waiters, []
            for waiter in waiters:
                # Through the waiter's own loop, which may run on another thread.
                waiter.get_loop().call_soon_threadsafe(_wake, waiter)

    async def idle(self, timeout: float) -> bool:
        """Wait until nothing is under way, for at most ``timeout``; whether it got there."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while self.count:
            left = deadline - loop.time()
            if left <= 0:
                return False
            waiter = loop.create_future()
            self.waiters.append(waiter)
            try:
                await asyncio.wait({waiter}, timeout=left)
            finally:
                if not waiter.done():
                    waiter.cancel()
                    if waiter in self.waiters:
                        self.waiters.remove(waiter)
        return True


def _wake(waiter: asyncio.Future[None]) -> None:
    if not waiter.done():
        waiter.set_result(None)


_IN_FLIGHT: weakref.WeakKeyDictionary[AesGcmCipher, _InFlight] = weakref.WeakKeyDictionary()

#: How long the close waits, for reservations under way and for the store's ``hold``, before it
#: closes the bound. A reserve not overspent is then left as it is, an over-count of at most a block
#: (:func:`_close_unsettled`); an overspent one waits on for ``hold`` with no bound and is charged.
#: A reservation that lands after the settlement is a block persisted but never spent, an
#: over-count. engine.stop()'s store-close floor (``pipeline/engine.py`` ``_STORE_CLOSE_FLOOR``)
#: counts this wait, which is not the whole of the close's: ``_writer_guard``'s own entry rollback
#: of a transaction a cut writer abandoned can run past it, and so can the overspent wait.
SETTLE_WAIT_SECONDS = 0.1


def _in_flight(bound: AesGcmCipher) -> _InFlight:
    entry = _IN_FLIGHT.get(bound)
    if entry is None:
        entry = _IN_FLIGHT[bound] = _InFlight()
    return entry


@contextmanager
def _counted(bound: AesGcmCipher) -> Iterator[None]:
    """Count a reservation or settlement as under way on ``bound`` for :func:`settle_at_close`."""
    entry = _in_flight(bound)
    entry.count += 1
    try:
        yield
    finally:
        entry.leave()


async def _apply(bound: AesGcmCipher, need: int, add: AddInvocations, failed: str) -> bool:
    """Persist ``need`` and hand it to the cipher; log ``failed`` and return False when the DB
    refuses."""
    try:
        total = await add(bound.invocation_key_id, need)
    except Exception:  # noqa: BLE001 — advisory accounting must never fail an engine operation
        log.warning(failed, exc_info=True)
        return False
    # A settlement grant zeroes the reserve exactly (remaining was `-need`), so a repeated settle is a
    # no-op — in EITHER direction, an overspend charged or an unspent reserve refunded; a refill grant
    # hands over a fresh block.
    bound.grant_invocations(need, total)
    return True


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


async def checkpoint_invocations(
    cipher: Cipher | None, add: AddInvocations, *, settle: bool = False
) -> int | None:
    """Reconcile the live cipher's spend against its persisted reserve; return the cumulative total.

    ``settle=False`` (the periodic checkpoint) tops the reserve back up to a whole block once it falls
    below half, keeping the persisted total AHEAD of what has been spent.

    ``settle=True`` squares the persisted total with what was ACTUALLY spent, charging an overspend
    and refunding an unspent reserve, and reserves nothing further. Idempotent: a second settle finds
    nothing to correct. No engine path settles through here since BACKLOG #3191: the store's close
    settles through :func:`settle_at_close`, which also closes the bound.

    Returns ``None`` when the store's cipher carries no bound (identity / ``vault_transit``). Never
    raises: a checkpoint that cannot reach the DB is logged and retried next pass — the in-process
    ceiling still holds meanwhile, so a transient DB blip must not take the engine down."""
    bound = bounded_cipher(cipher)
    if bound is None:
        return None
    if not bound.invocation_bound_enabled:
        # First contact: switch the cipher onto the persisted bound so the very first block is
        # reserved before it is spent.
        bound.enable_invocation_bound()
    with _counted(bound):
        need = bound.invocation_settlement() if settle else bound.invocation_reserve_shortfall()
        if need:
            await _apply(
                bound,
                need,
                add,
                "could not checkpoint the AES-GCM invocation bound for the active key; the "
                "in-process ceiling still applies and the next pass retries",
            )
    return bound.cumulative_invocations()


async def settle_at_close(
    cipher: Cipher | None,
    add: AddInvocations,
    *,
    hold: Callable[[], AbstractAsyncContextManager[object]] | None = None,
) -> int | None:
    """The store's close: settle the bound and close it, in one step (BACKLOG #3191).

    It waits until no reservation or settlement is under way on this cipher, then enters ``hold``
    and checks again, so none lands outside the figure; a store with a writer lock passes it as
    ``hold``, so a writer holding it, or queued for it first, finishes and is counted first. Then
    :meth:`AesGcmCipher.close_invocation_bound` reads the settlement and closes the bound under one
    hold of the cipher's counter lock, so the cipher raises
    :class:`~messagefoundry.store.crypto.CipherError` on every later encrypt rather than seal a value
    the persisted total leaves out. The settlement counts itself as under way, so an overlapping
    close waits for it and then finds nothing to correct, or retries one the DB refused.

    The waits share :data:`SETTLE_WAIT_SECONDS`. When ``hold`` is still busy then, the bound is
    closed at once. A reserve not overspent is left as it is, with no write
    (:func:`_close_unsettled`): an over-count of at most a block. An overspent one keeps waiting for
    ``hold``, with no bound, and is then charged, so the close does not under-count; that wait can
    run past engine.stop()'s budget. A writer still waiting for ``hold`` that then encrypts meets the
    closed bound and fails before it commits. A settlement the DB refuses is logged, and the bound
    stays closed. ``add`` runs inside ``hold``. Returns the cumulative total, or ``None`` when the
    cipher carries no bound."""
    bound = bounded_cipher(cipher)
    if bound is None:
        return None
    if not bound.invocation_bound_enabled:
        bound.enable_invocation_bound()
    entry = _in_flight(bound)
    if bound.invocation_bound_closed and not entry.count and not bound.invocation_settlement():
        return bound.cumulative_invocations()  # an earlier close settled it
    loop = asyncio.get_running_loop()
    deadline = loop.time() + SETTLE_WAIT_SECONDS
    try:
        while True:
            await entry.idle(max(0.0, deadline - loop.time()))
            async with contextlib.AsyncExitStack() as stack:
                if hold is not None and not await _enter_or_close(bound, stack, hold, deadline):
                    return bound.cumulative_invocations()
                # A reservation that began while this waited for ``hold`` is queued behind it, so
                # release and wait again, unless the wait has run out.
                if entry.count and loop.time() < deadline:
                    continue
                if entry.count:
                    log.warning(
                        "an AES-GCM invocation reservation was still under way at close; settling "
                        "without it, so a block it persists later is an over-count"
                    )
                with _counted(bound):
                    need = bound.close_invocation_bound()
                    if need:
                        await _apply(
                            bound,
                            need,
                            add,
                            "could not settle the AES-GCM invocation bound at close; the bound is "
                            "closed, so the cipher encrypts nothing more under its key",
                        )
                return bound.cumulative_invocations()
    finally:
        # Whatever ended the wait, entering ``hold`` raising included, the bound ends closed.
        if not bound.invocation_bound_closed:
            bound.close_invocation_bound()


async def _enter_or_close(
    bound: AesGcmCipher,
    stack: contextlib.AsyncExitStack,
    hold: Callable[[], AbstractAsyncContextManager[object]],
    deadline: float,
) -> bool:
    """Enter ``hold`` on ``stack``, and return True to settle under it.

    Past ``deadline`` the bound is closed, so nothing more is spent. A reserve not overspent then
    needs no write: the entry is given up and this returns False (:func:`_close_unsettled`). An
    overspent one keeps the same place in ``hold``'s queue and waits with no bound, so the
    settlement under it charges the overspend."""
    loop = asyncio.get_running_loop()
    entering = asyncio.ensure_future(stack.enter_async_context(hold()))
    try:
        done, _ = await asyncio.wait({entering}, timeout=max(0.0, deadline - loop.time()))
        if done:
            entering.result()
            return True
        if bound.close_invocation_bound() > 0:
            await asyncio.wait({entering})
            entering.result()
            return True
        entering.cancel()
        await asyncio.wait({entering})
        _close_unsettled(bound)
        # An entry that won the race with the cancel is on ``stack``, which releases it.
        return False
    except BaseException:
        if not entering.done():
            entering.cancel()
        raise


def _close_unsettled(bound: AesGcmCipher) -> None:
    """Log a close that gave up ``hold`` with a reserve not overspent: the bound is closed and no
    settlement is written, so the persisted total keeps this handle's unspent reserve, an over-count
    of at most a block, the direction this bound may drift in."""
    need = bound.close_invocation_bound()
    if need < 0:
        log.error(
            "the store's writer stayed busy past %.2fs at close, so the AES-GCM invocation bound was "
            "closed without refunding this handle's reservation, an over-count of %d",
            SETTLE_WAIT_SECONDS,
            -need,
        )


def reopen_invocation_bound(cipher: Cipher | None) -> None:
    """Open the bound a closed store left closed, for a store opening on the same cipher, before
    anything on it encrypts. A no-op for a cipher with no bound."""
    bound = bounded_cipher(cipher)
    if bound is not None:
        bound.reopen_invocation_bound()


async def reserve_invocations_ahead(cipher: Cipher | None, add: AddInvocations, count: int) -> None:
    """Reserve enough of the persisted bound to cover a burst of ``count`` encrypts BEFORE it starts.

    For a burst that cannot top the reserve up part-way. The at-open seal of one (table, column)
    surface runs as ONE transaction (BACKLOG #1169), so a crash leaves the surface all sealed or all
    unsealed. On SQLite a reservation commits the one writer connection, so reserving mid-surface would
    commit the surface half-sealed -- exactly the mixed state the refusal would then reject as
    tampering. Reserving the whole burst up front keeps the one invariant this bound rests on: the
    persisted total leads every encrypt, so an unclean exit can only OVER-count. A crash mid-surface
    forfeits the reservation for encrypts the rollback discarded, which is that same conservative bias.

    Same failure contract as :func:`checkpoint_invocations`: a reservation that cannot reach the DB is
    logged and the burst proceeds under the in-process ceiling, which still applies."""
    bound = bounded_cipher(cipher)
    if bound is None or count <= 0:
        return
    if not bound.invocation_bound_enabled:
        bound.enable_invocation_bound()
    with _counted(bound):
        need = bound.invocation_reserve_shortfall(ahead=count)
        if need:
            await _apply(
                bound,
                need,
                add,
                "could not reserve the AES-GCM invocation bound ahead of an at-rest seal; the "
                "in-process ceiling still applies",
            )


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
