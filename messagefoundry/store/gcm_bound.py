# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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

**Rotation semantics.** ``key_id`` is a one-way SHA-256 fingerprint of the DEK, so a NEW key simply has
no row and starts at zero — no reset operation is needed, and none is offered. Zeroing an EXISTING
key_id's row is deliberately *not* implemented: it would let an operator refresh the birthday budget of a
key they never actually changed, defeating the whole control. Re-supplying a retired key resolves to its
existing row and inherits its accumulated count.

**Out of scope: ``vault_transit``.** That cipher draws no local nonce and builds no local ``AESGCM``;
key lifetime is Vault's to manage. :func:`bounded_cipher` returns ``None`` for it and for the identity
cipher, and every entry point here degrades to a no-op.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable

from messagefoundry.store.crypto import _GCM_RESERVE_BLOCK, AesGcmCipher, Cipher

__all__ = [
    "GCM_RESERVE_BLOCK",
    "bounded_cipher",
    "checkpoint_invocations",
]

log = logging.getLogger(__name__)

#: Public alias of the reserve block size (tests + the runner read it; the cipher owns the value).
GCM_RESERVE_BLOCK = _GCM_RESERVE_BLOCK

#: ``(key_id, count) -> new cumulative total``. Each backend supplies its own atomic upsert-add. ``count``
#: is normally positive (a reservation); a settlement may pass a NEGATIVE count to refund an unspent
#: reserve, which every backend's ``invocations = invocations + ?`` upsert handles unchanged.
AddInvocations = Callable[[str, int], Awaitable[int]]


def bounded_cipher(cipher: Cipher | None) -> AesGcmCipher | None:
    """The cipher whose invocations the store must account for, or ``None``.

    Only the in-process AES-GCM keyring draws local nonces under a local key, so only it has a birthday
    budget this store can bound. The identity cipher encrypts nothing; ``TransitCipher`` encrypts inside
    the vault under a key the vault versions."""
    return cipher if isinstance(cipher, AesGcmCipher) else None


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
            total = await add(bound.active_key_id, need)
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
