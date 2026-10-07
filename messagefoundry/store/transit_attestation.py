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

THE ROW IS BOUND TO ITS AUDIT ROW, so DML on the table alone forges nothing. The row carries the
sequence number and chain hash of the audit row its write appended. Every read checks that audit row:
it must be in the log, be the newest attest or withdraw row, say the same key name, reason, actor and
time, carry the recorded hash, and verify under the audit key of its own range. A row that fails any of
these reads as UNATTESTED, with the reason in ``audit_gap``. A forger would need the audit key, which on
``vault_transit`` lives inside Transit. Deleting a later withdraw row to replay an older attestation
breaks the chain, which ``audit-verify`` and the start-up chain walk report, and this check does not.

The binding is to the key NAME only. A store pointed at another Vault, or another Transit mount, that
holds a key with the same name keeps the attestation. That follows the 2026-10-07 ruling.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from messagefoundry.config.ai_policy import SecurityEnforcement

if TYPE_CHECKING:
    from messagefoundry.store.store import OperatorAudit

__all__ = [
    "TRANSIT_BOUND_ATTESTED_ACTION",
    "TRANSIT_BOUND_KEY_NAME_MAX",
    "TRANSIT_BOUND_REASON_MAX",
    "TRANSIT_BOUND_WITHDRAWN_ACTION",
    "TransitBoundAttestation",
    "TransitBoundAttestationStore",
    "TransitBoundUnattestedError",
    "enforce_transit_bound_attestation",
    "read_transit_bound_attestation",
    "transit_bound_gap",
    "utf16_units",
]

log = logging.getLogger(__name__)

#: The audit action ``store attest-transit-bound`` commits with the row.
TRANSIT_BOUND_ATTESTED_ACTION = "store.transit_bound_attested"
#: The audit action ``store withdraw-transit-bound`` commits with the delete.
TRANSIT_BOUND_WITHDRAWN_ACTION = "store.transit_bound_withdrawn"
#: The longest reason the command accepts, in UTF-16 code units, because SQL Server's
#: ``NVARCHAR(1000)`` counts those and not code points. A character outside the Basic Multilingual
#: Plane counts twice. SQLite and Postgres store ``TEXT``, so the SQL Server width is the bound.
TRANSIT_BOUND_REASON_MAX = 1000
#: The longest Transit key name the command records, in UTF-16 code units: SQL Server's
#: ``key_name NVARCHAR(256)``, which is also ``audit_log.actor``'s width.
TRANSIT_BOUND_KEY_NAME_MAX = 256


def utf16_units(text: str) -> int:
    """``text``'s length as SQL Server's ``NVARCHAR`` counts it: UTF-16 code units."""
    return len(text.encode("utf-16-le", "surrogatepass")) // 2


@dataclass(frozen=True, slots=True)
class TransitBoundAttestation:
    """The one recorded attestation. Non-secret: a key NAME, the operator's reason, who and when.

    ``audit_seq`` and ``audit_hash`` name the audit row the write appended. ``audit_gap`` is set on a
    READ, when that audit row does not back this one; the row then counts as no attestation."""

    key_name: str
    reason: str
    actor: str
    attested_at: float
    audit_seq: int | None = None
    audit_hash: str | None = None
    audit_gap: str | None = None


@runtime_checkable
class TransitBoundAttestationStore(Protocol):
    """The store slice that holds the attestation. All three shipped backends implement it.

    A separate protocol, as ``SecretRotationMetaStore`` is, so the engine narrows with
    ``isinstance``. A store that does not implement it reads as having no attestation, which refuses
    under enforce: the fail-closed direction."""

    async def get_transit_bound_attestation(self) -> TransitBoundAttestation | None:
        """The recorded attestation, or ``None`` when none is recorded. The row comes back with
        ``audit_gap`` set when its audit row does not back it (see the module docstring)."""
        ...

    async def record_transit_bound_attestation(
        self, *, key_name: str, reason: str, actor: str, now: float | None = None
    ) -> TransitBoundAttestation:
        """Record ``key_name`` as attested by ``actor``, replacing any earlier row. The store writes
        the ``store.transit_bound_attested`` audit row itself, in the same transaction, and stores its
        sequence number and hash in the attestation row."""
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


async def read_transit_bound_attestation(store: object) -> TransitBoundAttestation | None:
    """The attestation as the start gate and ``GET /security/posture`` both read it. A store without
    the slice reads as having none, which refuses under enforce: the fail-closed direction."""
    if not isinstance(store, TransitBoundAttestationStore):
        return None
    return await store.get_transit_bound_attestation()


def transit_bound_gap(key_name: str, attestation: TransitBoundAttestation | None) -> str | None:
    """Why ``attestation`` does not cover ``key_name``, or ``None`` when it does.

    The comparison is exact. Transit key names are case-sensitive, so a near match is another key."""
    if attestation is None:
        return f"no attestation is recorded for the Transit data key {key_name!r}"
    if attestation.audit_gap is not None:
        return (
            "the recorded attestation is not backed by its audit row, so it counts as none: "
            f"{attestation.audit_gap}. Only `messagefoundry store attest-transit-bound` writes a "
            "row that counts"
        )
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
    attestation = await read_transit_bound_attestation(store)
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
