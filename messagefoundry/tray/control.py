# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tray service-control wrapper (ADR 0113 §4).

Thin adapter over the shipped, injection-hardened ``messagefoundry.service.control_service_ex`` —
the tray writes **no** new privileged code and elevates only a System32 ``cmd``/``net`` (never the
venv interpreter). The pure helpers (confirm text, outcome→toast) are unit-tested; :func:`perform`
is the one-line elevation call the shell invokes after the confirm dialog.
"""

from __future__ import annotations

from messagefoundry.service import ServiceControlOutcome, control_service_ex
from messagefoundry.tray.state import Toast

# Actions that halt (or briefly halt) message flow → confirm before elevating.
_CONFIRM_ACTIONS = frozenset({"stop", "restart"})
_VERBS = {"start": "Start", "stop": "Stop", "restart": "Restart"}


def needs_confirm(action: str) -> bool:
    """Stop/Restart get a confirm dialog (they halt a clinical interface); Start does not."""
    return action in _CONFIRM_ACTIONS


def confirm_text(action: str, service_name: str) -> str:
    """The confirm-dialog body for a consequential action."""
    verb = _VERBS.get(action, action.capitalize())
    return f"{verb} the {service_name} service? This halts message flow while it is down."


def outcome_toast(action: str, outcome: ServiceControlOutcome) -> Toast | None:
    """The balloon (if any) for a completed elevation attempt.

    A successful dispatch returns ``None`` — the poller's own transition toast announces the new
    running/stopped state, so a second balloon would be noise. Cancel/failure/unsupported each get
    an explicit, honest message.
    """
    if outcome is ServiceControlOutcome.CANCELLED:
        return Toast("MessageFoundry", "Action cancelled")
    if outcome is ServiceControlOutcome.FAILED:
        return Toast("MessageFoundry", f"Service {action} failed — see the service log")
    if outcome is ServiceControlOutcome.UNSUPPORTED:
        return Toast("MessageFoundry", "Service control is Windows-only")
    return None  # DISPATCHED


def perform(action: str, service_name: str) -> ServiceControlOutcome:
    """Elevate the action via the shipped, hardened control path. One UAC prompt."""
    return control_service_ex(action, service_name)
