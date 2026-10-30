# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Startup preflight on the **privileges of each Vault token** the engine uses (BACKLOG #2903,
ADR 0216, ASVS 13.2.2).

``serve`` runs it after the store opens and before any listener binds, beside the store privilege
preflight (:mod:`messagefoundry.store.privilege`, ADR 0199) and under the same teardown discipline.
It probes each Vault consumer with the probe ``check-privileges`` runs
(:func:`messagefoundry.privilege_probes.probe_vault`): a client built by the provider's own
constructor, with the token read again from the source the provider reads it from, so a token
replaced between the store open and this read is the one judged. It judges the readings with
:func:`messagefoundry.privilege_check.vault_hops`.

**What it refuses is** :func:`~messagefoundry.privilege_check.vault_preflight_outcome` **and nothing
else.** Under ``[security].enforcement = enforce`` a grant in the refusing class -- the root policy,
any grant on an administrative path, a Transit key's ``config``, ``rotate``, ``export`` or
``backup`` -- refuses the start, unless ``[security].allow_over_granted_vault_token`` accepts it
(audited). Every other over-grant warns and writes an audit row. So does a probe that could not
observe the token for a reason the ruling excuses: a network failure, a timeout or a 403
(:func:`~messagefoundry.privilege_probes.excused_failure`). Any other failure -- a ``TypeError``
after an hvac signature drift, an engine refusal, any other Vault error -- left the token unjudged,
so under ``enforce`` it refuses the start, and the opt-out does not lift that refusal. Under
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
from messagefoundry.privilege_probes import VaultTokenReading, excused_failure
from messagefoundry.store.privilege import PreflightOutcome

if TYPE_CHECKING:  # pragma: no cover - typing only
    from messagefoundry.config.settings import ServiceSettings

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
    """Each consumer's reading. A probe that raises never aborts the start here: the probe reports
    its own failures, but a token re-read or an unrouted consumer kind can still raise, and under
    ``enforcement = warn`` nothing here may refuse. The raise becomes a reading with one problem.
    Unless :func:`~messagefoundry.privilege_probes.excused_failure` excuses it, the reading also
    names it in ``unexcused``, which refuses under ``enforce``: a code defect is never a pass. Only
    the exception's type is kept, so no library or server text reaches the log or the audit row."""
    out: list[VaultTokenReading] = []
    for consumer in consumers:
        try:
            out.append(probe(consumer))
        except Exception as exc:  # noqa: BLE001 - classified below, never a pass
            name = type(exc).__name__
            problem = f"the probe raised {name}"
            log.warning("vault privilege preflight: %s: %s", consumer.hop, problem)
            unexcused = () if excused_failure(exc) else (name,)
            out.append(VaultTokenReading(problems=(problem,), unexcused=unexcused))
    return out


def _unjudged_reason(hops: list[str]) -> str:
    """Why an enforcing start refuses the named Vault hops, whose probe failed unexcused."""
    return (
        f"the Vault privilege probe on {', '.join(hops)} failed for a reason that is not a network "
        "failure, a timeout or a 403, so the token was never judged, under [security].enforcement "
        f"= 'enforce'. {VAULT_OVER_GRANT_OPT_OUT} does not accept this; fix the cause the "
        "preflight's warning names, or set enforcement = 'warn'"
    )


async def run_vault_privilege_preflight(
    settings: ServiceSettings,
    store: VaultAuditStore,
    *,
    enforcing: bool,
    over_grant_accepted: bool,
    probe: Callable[[VaultConsumer], VaultTokenReading],
) -> list[HopPrivilege]:
    """Probe every Vault token ``settings`` puts to use, report each, and refuse where
    :func:`~messagefoundry.privilege_check.vault_preflight_outcome` says so, and, under ``enforce``,
    where a reading names a failure in ``unexcused``.

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
    unjudged: list[str] = []
    for hop, reading in zip(hops, readings, strict=True):
        outcome = vault_preflight_outcome(
            hop, enforcing=enforcing, over_grant_accepted=over_grant_accepted
        )
        if enforcing and reading.unexcused:
            # Not the opt-out's to lift: it accepts a grant that was seen, and this token was never
            # fully read. A grave grant seen beside the failure still refuses for its own reason.
            if outcome is not PreflightOutcome.REFUSE:
                unjudged.append(hop.hop)
            outcome = PreflightOutcome.REFUSE
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
            "unexcused": list(reading.unexcused),
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
        if refusing and hop.hop not in unjudged:
            refused.append(hop.hop)
    reasons = [
        *([vault_refusal_reason(refused)] if refused else []),
        *([_unjudged_reason(unjudged)] if unjudged else []),
    ]
    if reasons:
        raise VaultPrivilegeError(f"{'; and '.join(reasons)}; refusing to start")
    return hops
