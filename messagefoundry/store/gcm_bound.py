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
keyed on the DEK, so ``[store].aad_bind = false`` keeps the old exposure (ADR 0196).

**Rotation semantics.** A NEW DEK derives new sub-keys, so it has no row and starts at zero -- no reset
operation is needed, and none is offered. Zeroing an EXISTING key_id's row is deliberately *not*
implemented: it would let an operator refresh the birthday budget of a key they never actually changed,
defeating the whole control. Re-supplying a retired DEK to the same store resolves to its existing
sub-key row and inherits its accumulated count. What the engine cannot see is a store file copied or
rolled back outside it -- a VM snapshot, a DBA restore of a server database, a staging copy given the
production key: that copy carries its salt and its row. ADR 0196 records it as an accepted limit.

**Out of scope: ``vault_transit``.** That cipher draws no local nonce and builds no local ``AESGCM``.
:func:`bounded_cipher` returns ``None`` for it and for the identity cipher, and every entry point here
degrades to a no-op. So nothing counts, alarms or refuses on that path. Its bound is a DOCUMENTED
OPERATOR PRECONDITION, not a counted one: the operator must rotate the Transit data key before any one
key version seals 2**32 values, and the engine does not check that they do. It is weaker than this
module's bound, and the owner ruled on 2026-09-28 that it does not meet ASVS 11.5.2 ruling R3, which
needs an engine-recorded attestation. ADR 0138's 2026-09-28 amendment states the precondition and why
(BACKLOG #1173). That attestation is :mod:`messagefoundry.store.transit_attestation` (BACKLOG #2337,
ADR 0138's 2026-10-07 amendment): a CLI-written, audited store row naming the Transit key, without which
``serve`` refuses under enforce. It records who vouched for the rotation; it still counts nothing.
"""

from __future__ import annotations

import logging
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
    "bind_store_salt",
    "bounded_cipher",
    "checkpoint_invocations",
    "counts_under_dek",
    "reserve_invocations_ahead",
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


def bounded_cipher(cipher: Cipher | None) -> AesGcmCipher | None:
    """The cipher whose invocations the store must account for, or ``None``.

    Only the in-process AES-GCM keyring draws local nonces under a local key, so only it has a birthday
    budget this store can bound. The identity cipher encrypts nothing; ``TransitCipher`` encrypts inside
    the vault, and its bound is the operator's rotation of the Transit key, which nothing here counts
    (the module docstring's ``vault_transit`` paragraph)."""
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

    ``settle=True`` (store close, and the end of a long offline burst) squares the persisted total with
    what was ACTUALLY spent — charging an overspend, refunding an unspent reserve — and reserves nothing
    further. So ``rotate-key``'s millions of re-encrypts are accounted even where they outran the refill
    cadence, while a short-lived CLI process that encrypted a handful of values does not permanently burn
    a whole 2**16 block of the key's budget. Idempotent: a second settle finds nothing to correct.

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
    need = bound.invocation_settlement() if settle else bound.invocation_reserve_shortfall()
    if need:
        try:
            total = await add(bound.invocation_key_id, need)
        except Exception:  # noqa: BLE001 — advisory accounting must never fail an engine operation
            log.warning(
                "could not checkpoint the AES-GCM invocation bound for the active key; the "
                "in-process ceiling still applies and the next pass retries",
                exc_info=True,
            )
            return bound.cumulative_invocations()
        # A settlement grant zeroes the reserve exactly (remaining was `-need`), so a repeated settle is a
        # no-op — in EITHER direction, an overspend charged or an unspent reserve refunded; a refill grant
        # hands over a fresh block.
        bound.grant_invocations(need, total)
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

    Same failure contract as :func:`checkpoint_invocations`: a reservation that cannot reach the DB is
    logged and the burst proceeds under the in-process ceiling, which still applies."""
    bound = bounded_cipher(cipher)
    if bound is None or count <= 0:
        return
    if not bound.invocation_bound_enabled:
        bound.enable_invocation_bound()
    need = bound.invocation_reserve_shortfall(ahead=count)
    if not need:
        return
    try:
        total = await add(bound.invocation_key_id, need)
    except Exception:  # noqa: BLE001 — advisory accounting must never fail an engine operation
        log.warning(
            "could not reserve the AES-GCM invocation bound ahead of an at-rest seal; the "
            "in-process ceiling still applies",
            exc_info=True,
        )
        return
    bound.grant_invocations(need, total)


async def bind_store_salt(cipher: Cipher | None, ensure: EnsureSalt) -> None:
    """Bind the store's persisted salt into its cipher, minting it on a store that has none (ADR 0196).

    Runs at open, BEFORE the first checkpoint and before anything seals, so the first reserved block
    and the first value both land under this store's own sub-key. A store with no salt row is a new
    store or a restored one, and the salt minted here makes its data key new. No-op for the identity
    cipher and ``vault_transit``, which have no local key, and for the frozen v1 writer, which has no
    salt field.

    Unlike the checkpoint, a failure here RAISES: the open cannot pick the key it seals under without
    it, and a guessed salt would split one store's values across keys no row accounts for."""
    bound = bounded_cipher(cipher)
    if bound is None or bound.store_salt is None:
        return
    salt_hex = await ensure(new_store_salt().hex())
    bound.bind_store_salt(parse_store_salt(salt_hex))
