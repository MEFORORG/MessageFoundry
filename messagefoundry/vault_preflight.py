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
else**, which ADR 0216 and ``docs/SECURITY.md`` (*What serve does with a Vault finding*) describe:
under ``[security].enforcement = enforce``, a grant in the refusing class unless
``[security].allow_over_granted_vault_token`` accepts it (audited), and a probe failure that is not
a network failure, a timeout or a 403 (:func:`~messagefoundry.privilege_probes.excused_failure`),
which the opt-out does not lift. Every other finding warns and writes an audit row. Under ``warn``
nothing refuses.

**Every finding also raises an alert, and a clean read resolves it** (slice B). A hop that is not
clean fires ``vault_privilege_warning`` BEFORE any refusal, so a refused start still pages, as the
store preflight's ``store_privilege_warning`` does; a hop read clean fires
``vault_privilege_clean``, which auto-resolves an open warning for the same hop and pages nobody.
The subject is the hop alone (:func:`vault_privilege_alert_subject`), never anything about the
token, so processes that share one store share each hop's alert: a clean start by one resolves the
warning another raised on a different token.

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
    HopState,
    VaultConsumer,
    vault_consumers,
    vault_hops,
    vault_preflight_outcome,
    vault_refusal_reason,
)
from messagefoundry.privilege_probes import VaultTokenReading, unexcused_cause
from messagefoundry.store.privilege import PreflightOutcome

if TYPE_CHECKING:  # pragma: no cover - typing only
    from messagefoundry.config.settings import ServiceSettings

log = logging.getLogger(__name__)

__all__ = [
    "VAULT_PRIVILEGE_ALERT_SUBJECT",
    "VAULT_PRIVILEGE_AUDIT_ACTION",
    "VaultAuditStore",
    "VaultPrivilegeAlertSink",
    "VaultPrivilegeError",
    "run_vault_privilege_preflight",
    "vault_privilege_alert_subject",
]

#: The audit action of the row each probed Vault hop writes at every start.
VAULT_PRIVILEGE_AUDIT_ACTION = "vault_privilege_preflight"

#: The longest hop detail an audit row keeps. The detail lists each path asked about with its
#: capabilities, so a token with many policies makes a long one; the refusing reasons are kept
#: whole in their own field.
_AUDIT_DETAIL_LIMIT = 2000


class VaultPrivilegeError(RuntimeError):
    """Raised by the preflight when ``vault_preflight_outcome`` refuses a Vault hop under
    ``enforce``: a grant in the refusing class with no accepted opt-out, or an unexcused probe
    failure. The caller refuses to start before any listener binds."""


class VaultAuditStore(Protocol):
    """The one store method this preflight calls."""

    async def record_audit(self, action: str, *, actor: str | None, detail: str | None) -> None: ...


class VaultPrivilegeAlertSink(Protocol):
    """The two :class:`~messagefoundry.pipeline.alerts.AlertSink` methods this preflight calls,
    named here as :class:`~messagefoundry.store.privilege.PrivilegeAlertSink` names the store's;
    every ``AlertSink`` satisfies it structurally."""

    def vault_privilege_warning(
        self, name: str, *, finding: str, refusing_count: int, detail: str
    ) -> None: ...

    def vault_privilege_clean(self, name: str) -> None: ...


#: The alert subject's prefix (the ``connection`` key the notifier throttles and keys durable state
#: on). :func:`vault_privilege_alert_subject` adds a colon after it, which keeps every subject
#: outside the connection-name grammar; the bare prefix is a legal connection name.
VAULT_PRIVILEGE_ALERT_SUBJECT = "vault"


def vault_privilege_alert_subject(hop: HopPrivilege) -> str:
    """``vault:<hop>``, as ``vault:store`` or ``vault:secrets``.

    Keyed by the hop and by nothing about the token: fixing an over-grant usually means a new token
    with other policies, and a subject that followed the token would leave the old warning open
    for ever. The cost is the one the module docstring names for a shared store."""
    return f"{VAULT_PRIVILEGE_ALERT_SUBJECT}:{hop.hop.removeprefix('vault.')}"


def _alert(sink: VaultPrivilegeAlertSink, hop: HopPrivilege, outcome: PreflightOutcome) -> None:
    """Raise the hop's warning when ``outcome`` (from
    :func:`~messagefoundry.privilege_check.vault_preflight_outcome`) is a finding, or its clean
    inverse when the hop read clean; any other state judged nothing, so it raises neither. Best
    effort, like the audit row: a sink that raises is logged and never masks the finding or the
    refusal."""
    subject = vault_privilege_alert_subject(hop)
    try:
        if outcome is not PreflightOutcome.CLEAN:
            sink.vault_privilege_warning(
                subject,
                finding=hop.state.value,
                refusing_count=len(hop.refusing),
                detail=scrub_log_argument(hop.detail)[:_AUDIT_DETAIL_LIMIT],
            )
        elif hop.state is HopState.CLEAN:
            sink.vault_privilege_clean(subject)
    except Exception:  # noqa: BLE001 - alerting is best-effort; never mask the finding
        log.exception("vault privilege preflight: the alert sink raised")


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
            problem = f"the probe raised {type(exc).__name__}"
            log.warning("vault privilege preflight: %s: %s", consumer.hop, problem)
            cause = unexcused_cause(exc)
            unexcused = () if cause is None else (cause,)
            out.append(VaultTokenReading(problems=(problem,), unexcused=unexcused))
    return out


async def run_vault_privilege_preflight(
    settings: ServiceSettings,
    store: VaultAuditStore,
    *,
    enforcing: bool,
    over_grant_accepted: bool,
    probe: Callable[[VaultConsumer], VaultTokenReading],
    alert_sink: VaultPrivilegeAlertSink | None = None,
) -> list[HopPrivilege]:
    """Probe every Vault token ``settings`` puts to use, report each, and refuse where
    :func:`~messagefoundry.privilege_check.vault_preflight_outcome` says so.

    ``probe`` is :func:`~messagefoundry.privilege_probes.probe_vault` bound to the settings and the
    instance hop posture; it makes network calls and an hvac client, so it runs off the event loop.
    With no Vault consumer configured nothing is probed and no row is written, as SQLite's store
    preflight writes none.

    Each probed hop writes one ``vault_privilege_preflight`` audit row, best-effort, BEFORE any
    refusal, so a refused start is durable. With an ``alert_sink``, each hop also raises
    ``vault_privilege_warning``, or ``vault_privilege_clean`` when it reads clean, best-effort and
    before any refusal. Returns the judged hops.

    Raises :class:`VaultPrivilegeError` naming every refused hop."""
    consumers = vault_consumers(settings)
    if not consumers:
        return []
    readings = await asyncio.to_thread(_probe_all, consumers, probe)
    hops = vault_hops(consumers, readings)
    outcomes = [
        vault_preflight_outcome(hop, enforcing=enforcing, over_grant_accepted=over_grant_accepted)
        for hop in hops
    ]
    refused = [h for h, o in zip(hops, outcomes, strict=True) if o is PreflightOutcome.REFUSE]
    for hop, outcome in zip(hops, outcomes, strict=True):
        refusing = outcome is PreflightOutcome.REFUSE
        # An accepted grant is recorded as accepted only where the start goes ahead: with another
        # hop refusing, the opt-out let nothing start.
        accepted = outcome is PreflightOutcome.ACCEPTED and not refused
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
        if accepted:
            log.warning(
                "AUDIT: starting an enforcing instance on an over-granted Vault token (%s) because "
                "%s=true -- the token holds the root policy or a grant on an administrative path "
                "(Vault privilege opt-out override)",
                hop.hop,
                VAULT_OVER_GRANT_OPT_OUT,
            )
        if alert_sink is not None:
            _alert(alert_sink, hop, outcome)
        detail = {
            "hop": hop.hop,
            "state": hop.state.value,
            "refusing": list(hop.refusing),
            "unexcused": list(hop.unexcused),
            "detail": hop.detail[:_AUDIT_DETAIL_LIMIT],
            "enforcing": enforcing,
            "refused": refusing,
            "over_grant_accepted": accepted,
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
    if refused:
        reason = vault_refusal_reason(refused, over_grant_accepted=over_grant_accepted)
        raise VaultPrivilegeError(f"{reason}; refusing to start")
    return hops
