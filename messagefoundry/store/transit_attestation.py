# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The recorded attestation that stands in for the AES-GCM invocation bound on ``vault_transit``.

On ``[store].cipher_provider = "vault_transit"`` the engine keeps no AES-GCM invocation count:
:func:`~messagefoundry.store.gcm_bound.bounded_cipher` returns ``None``, because the cipher draws no
local nonce. The bound is the operator's rotation of the Transit data key, which must happen before
any one key version seals 2**32 values. The owner ruled on 2026-09-28 that a documented precondition
does not meet ASVS 11.5.2 ruling R3, and on 2026-10-07 settled what does (BACKLOG #2337):

1. The engine records WHO attested and WHEN. A reasoned config declaration is not enough.
2. The record is one audited row in the store, on all three backends. Only a CLI command writes it
   (``messagefoundry store attest-transit-bound``), with a ``cli:<osuser>`` actor, and its audit row
   commits in the same transaction. There is no API endpoint and no RBAC permission for it.
3. It binds to the Transit data-key NAME. A store pointed at another key name is not attested.
   Rotating versions inside one key keeps it, because the operator attests to that key's rotation
   policy. ``messagefoundry store withdraw-transit-bound`` removes it, audited the same way.

``serve`` reads it at start (:func:`enforce_transit_bound_attestation`, called from
:meth:`Engine.start`). With no match it REFUSES under ``[security].enforcement = enforce`` and warns
otherwise. No settings key stands in for the row.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from messagefoundry.config.ai_policy import SecurityEnforcement

if TYPE_CHECKING:
    from messagefoundry.store.store import AuditAppend, OperatorAudit

__all__ = [
    "TRANSIT_BOUND_ATTESTED_ACTION",
    "TRANSIT_BOUND_REASON_MAX",
    "TRANSIT_BOUND_WITHDRAWN_ACTION",
    "TransitBoundAttestation",
    "TransitBoundAttestationStore",
    "TransitBoundUnattestedError",
    "enforce_transit_bound_attestation",
    "transit_bound_gap",
]

log = logging.getLogger(__name__)

#: The audit action ``store attest-transit-bound`` commits with the row.
TRANSIT_BOUND_ATTESTED_ACTION = "store.transit_bound_attested"
#: The audit action ``store withdraw-transit-bound`` commits with the delete.
TRANSIT_BOUND_WITHDRAWN_ACTION = "store.transit_bound_withdrawn"
#: The longest reason the command accepts, in characters. It fits every backend's column.
TRANSIT_BOUND_REASON_MAX = 1000


@dataclass(frozen=True, slots=True)
class TransitBoundAttestation:
    """The one recorded attestation. Non-secret: a key NAME, the operator's reason, who and when."""

    key_name: str
    reason: str
    actor: str
    attested_at: float


@runtime_checkable
class TransitBoundAttestationStore(Protocol):
    """The store slice that holds the attestation. All three shipped backends implement it.

    A separate protocol, as ``SecretRotationMetaStore`` is, so the engine narrows with
    ``isinstance``. A store that does not implement it reads as having no attestation, which refuses
    under enforce: the fail-closed direction."""

    async def get_transit_bound_attestation(self) -> TransitBoundAttestation | None:
        """The recorded attestation, or ``None`` when none is recorded."""
        ...

    async def record_transit_bound_attestation(
        self, *, key_name: str, reason: str, audit: AuditAppend, now: float | None = None
    ) -> TransitBoundAttestation:
        """Record ``key_name`` as attested, replacing any earlier row, and append ``audit`` in the
        same transaction. ``audit.actor`` is stored as the row's actor."""
        ...

    async def withdraw_transit_bound_attestation(
        self, *, audit: OperatorAudit[TransitBoundAttestation], now: float | None = None
    ) -> TransitBoundAttestation | None:
        """Delete the recorded attestation and append the row ``audit`` builds from it, in one
        transaction. Returns what was withdrawn, or ``None`` (and appends nothing) when there was
        none."""
        ...


class TransitBoundUnattestedError(RuntimeError):
    """``serve`` refuses: the store runs on ``vault_transit`` and no recorded attestation names the
    configured Transit data key, under ``[security].enforcement = enforce`` (BACKLOG #2337).

    Raised from :meth:`Engine.start` before recovery or any listener, so a refused start touches
    nothing and the ASGI lifespan aborts."""


def transit_bound_gap(key_name: str, attestation: TransitBoundAttestation | None) -> str | None:
    """Why ``attestation`` does not cover ``key_name``, or ``None`` when it does.

    The comparison is exact. Transit key names are case-sensitive, so a near match is another key."""
    if attestation is None:
        return f"no attestation is recorded for the Transit data key {key_name!r}"
    if attestation.key_name != key_name:
        return (
            f"the recorded attestation names the Transit data key {attestation.key_name!r}, but the "
            f"store is configured with {key_name!r}; pointing the store at another key voids it"
        )
    return None


async def enforce_transit_bound_attestation(
    store: object, key_name: str | None, *, enforcement: SecurityEnforcement
) -> None:
    """The start gate. ``key_name`` is the live cipher's Transit data key, ``None`` off
    ``vault_transit`` (then this does nothing).

    Raises :class:`TransitBoundUnattestedError` under enforce when no recorded attestation names
    ``key_name``, and logs a WARNING otherwise. A store read that fails propagates in both modes:
    the start cannot tell whether the bound is attested, so it does not start."""
    if key_name is None:
        return
    attestation = (
        await store.get_transit_bound_attestation()
        if isinstance(store, TransitBoundAttestationStore)
        else None
    )
    gap = transit_bound_gap(key_name, attestation)
    if gap is None and attestation is not None:  # a gap of None always has an attestation
        log.info(
            "vault_transit AES-GCM invocation bound: Transit key %r attested by %s at %s",
            key_name,
            attestation.actor,
            attestation.attested_at,
        )
        return
    remedy = (
        "Record that this key's rotation policy keeps each key version under 2**32 encryptions "
        'with `messagefoundry store attest-transit-bound --reason "..."`'
    )
    if enforcement is SecurityEnforcement.ENFORCE:
        raise TransitBoundUnattestedError(
            f"refusing to start: [store].cipher_provider = 'vault_transit' and {gap}. The engine "
            "counts no AES-GCM invocations on this cipher, so an operator must attest the bound "
            f"(ASVS 11.3.4). {remedy}, or set [security].enforcement = warn to start with a warning."
        )
    log.warning(
        "[store].cipher_provider = 'vault_transit' and %s. The engine counts no AES-GCM invocations "
        "on this cipher and nobody has attested the bound (ASVS 11.3.4). Starting because "
        "[security].enforcement = warn; under enforce this start would be refused. %s.",
        gap,
        remedy,
    )
