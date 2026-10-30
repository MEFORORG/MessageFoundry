# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Startup preflight on the **privileges of each Vault token** the engine uses (BACKLOG #2903,
ADR 0216, ASVS 13.2.2).

``serve`` runs it after the store opens and before any listener binds, beside the store privilege
preflight (:mod:`messagefoundry.store.privilege`, ADR 0199) and under the same teardown discipline.
It probes each Vault consumer with the probe ``check-privileges`` runs
(:func:`messagefoundry.privilege_probes.probe_vault`), through the client and the token the provider
itself uses, and judges the readings with :func:`messagefoundry.privilege_check.vault_hops`.

**What it refuses is** :func:`~messagefoundry.privilege_check.vault_preflight_outcome` **and nothing
else.** Under ``[security].enforcement = enforce`` a grant in the refusing class -- the root policy,
any grant on an administrative path, a Transit key's ``config``, ``rotate``, ``export`` or
``backup`` -- refuses the start, unless ``[security].allow_over_granted_vault_token`` accepts it
(audited). Every other over-grant and an unobservable probe warn and write an audit row. Under
``warn`` nothing refuses.

**Not here yet:** the alert, with its auto-resolving inverse, that the row also asks for. It needs
a new alert event type in the notifier, which is a separate slice.

**Nothing secret is written.** A hop's detail names policy names, paths and capabilities, never a
token, an accessor or a digest of either; the log line escapes every control character a server
sent.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Callable
from functools import partial
from typing import TYPE_CHECKING, Protocol

from messagefoundry.audit_write import write_audit_soft
from messagefoundry.controlchars import scrub_log_argument
from messagefoundry.privilege_check import (
    VAULT_OVER_GRANT_OPT_OUT,
    HopPrivilege,
    VaultConsumer,
    vault_consumers,
    vault_hops,
    vault_preflight_outcome,
    vault_refusal_reason,
)
from messagefoundry.store.privilege import PreflightOutcome

if TYPE_CHECKING:  # pragma: no cover - typing only
    from messagefoundry.config.settings import ServiceSettings
    from messagefoundry.privilege_probes import VaultTokenReading

log = logging.getLogger(__name__)

__all__ = [
    "VAULT_PRIVILEGE_AUDIT_ACTION",
    "VaultAuditStore",
    "VaultPrivilegeError",
    "run_vault_privilege_preflight",
]

#: The audit action of the row each probed Vault hop writes at every start.
VAULT_PRIVILEGE_AUDIT_ACTION = "vault_privilege_preflight"

#: The longest hop detail an audit row keeps. The detail lists each path asked about with its
#: capabilities, so a token with many policies makes a long one; the refusing reasons are kept
#: whole in their own field.
_AUDIT_DETAIL_LIMIT = 2000


class VaultPrivilegeError(RuntimeError):
    """Raised by the preflight when a Vault token holds a grant in the refusing class under
    ``enforce``, with no accepted opt-out. The caller refuses to start before any listener binds."""


class VaultAuditStore(Protocol):
    """The one store method this preflight calls."""

    async def record_audit(self, action: str, *, actor: str | None, detail: str | None) -> None: ...


def _probe_all(
    consumers: list[VaultConsumer], probe: Callable[[VaultConsumer], VaultTokenReading]
) -> list[VaultTokenReading]:
    return [probe(c) for c in consumers]


async def run_vault_privilege_preflight(
    settings: ServiceSettings,
    store: VaultAuditStore,
    *,
    enforcing: bool,
    over_grant_accepted: bool,
    probe: Callable[[VaultConsumer], VaultTokenReading],
) -> list[HopPrivilege]:
    """Probe every Vault token ``settings`` puts to use, report each, and refuse where
    :func:`~messagefoundry.privilege_check.vault_preflight_outcome` says so.

    ``probe`` is :func:`~messagefoundry.privilege_probes.probe_vault` bound to the settings and the
    instance hop posture; it makes network calls and an hvac client, so it runs off the event loop.
    With no Vault consumer configured nothing is probed and no row is written, as SQLite's store
    preflight writes none.

    Each probed hop writes one ``vault_privilege_preflight`` audit row, best-effort, BEFORE any
    refusal, so a refused start is durable. Returns the judged hops.

    Raises :class:`VaultPrivilegeError` naming every refused hop."""
    consumers = vault_consumers(settings)
    if not consumers:
        return []
    readings = await asyncio.to_thread(_probe_all, consumers, probe)
    hops = vault_hops(consumers, readings)
    refused: list[str] = []
    for hop in hops:
        outcome = vault_preflight_outcome(
            hop, enforcing=enforcing, over_grant_accepted=over_grant_accepted
        )
        refusing = outcome is PreflightOutcome.REFUSE
        if outcome is PreflightOutcome.CLEAN:
            log.info("vault privilege preflight: %s %s", hop.hop, hop.state.value)
        else:
            log.warning(
                "vault privilege preflight: %s %s, enforcing=%s: %s%s",
                hop.hop,
                hop.state.value,
                enforcing,
                scrub_log_argument(hop.detail),
                "; REFUSING to start" if refusing else "",
            )
        if outcome is PreflightOutcome.ACCEPTED:
            log.warning(
                "AUDIT: starting an enforcing instance on an over-granted Vault token (%s) because "
                "%s=true -- the token holds the root policy or a grant on an administrative path "
                "(Vault privilege opt-out override)",
                hop.hop,
                VAULT_OVER_GRANT_OPT_OUT,
            )
        detail = {
            "hop": hop.hop,
            "state": hop.state.value,
            "refusing": list(hop.refusing),
            "detail": hop.detail[:_AUDIT_DETAIL_LIMIT],
            "enforcing": enforcing,
            "refused": refusing,
            "over_grant_accepted": outcome is PreflightOutcome.ACCEPTED,
        }
        # Best effort, and ``defects=()``: a raise here would mask the refusal below, as in the
        # store preflight (vault BACKLOG #2260).
        await write_audit_soft(
            partial(
                store.record_audit,
                VAULT_PRIVILEGE_AUDIT_ACTION,
                actor=None,
                detail=json.dumps(detail),
            ),
            log=log,
            message="vault privilege preflight: failed to record the audit row",
            defects=(),
        )
        if refusing:
            refused.append(hop.hop)
    if refused:
        raise VaultPrivilegeError(f"{vault_refusal_reason(refused)}; refusing to start")
    return hops
