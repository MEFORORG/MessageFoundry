# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Centralized field-level (property) authorization for API responses (WP-9; ASVS 8.1.2 / 8.2.3).

Some response properties carry PHI — the patient-identifying ``summary``, and exception text
(``error`` / ``last_error``) that can quote field values — and must be withheld from a caller who may
see the rest of the object but lacks the unlocking permission. This module is the **single declarative
place** that maps each PHI-bearing property to the :class:`~messagefoundry.auth.Permission` that
unlocks it, plus the one helper that enforces it. Centralizing it means the policy lives in one
auditable spot instead of being re-implemented inline per endpoint, where a new endpoint or field could
silently leak PHI (the Broken Object Property Level Authorization risk, ASVS 8.2.3).

**Read-side only.** The API exposes no client-writable PHI properties — mutations are coarse, separately
permission-gated actions (replay / purge / reload / connection-control) — so there is no per-field
*write* authorization surface today. See docs/SECURITY.md "Field-level authorization" for the model and
the trigger that would add one.

The full message **body** (``MessageDetail.raw``) is governed separately, at the endpoint, by the
coarser whole-body ``messages:view_raw`` gate — not by this per-property map.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TypeVar

from pydantic import BaseModel

from messagefoundry.api.models import (
    CapturedResponseInfo,
    DeadLetterRow,
    EventInfo,
    MessageDetail,
    MessageSummary,
    OutboxInfo,
)
from messagefoundry.auth import Identity, Permission

#: Response model → {property → Permission that unlocks it}. The single source of truth for which
#: response properties are PHI-gated and by which permission; :func:`redact_unauthorized` nulls a
#: property when the caller lacks its permission. Both summary-tier PHI fields gate on
#: ``messages:view_summary`` today (the body, gated by ``messages:view_raw``, is handled at the
#: endpoint). Add a row here when a new PHI-bearing response property is introduced.
PHI_FIELDS: dict[type[BaseModel], dict[str, Permission]] = {
    MessageSummary: {
        "summary": Permission.MESSAGES_VIEW_SUMMARY,
        "error": Permission.MESSAGES_VIEW_SUMMARY,
    },
    DeadLetterRow: {
        "summary": Permission.MESSAGES_VIEW_SUMMARY,
        "last_error": Permission.MESSAGES_VIEW_SUMMARY,
    },
    # The single-message detail view and its nested rows (#120). Redaction keys on the EXACT type
    # (no MRO walk), so MessageDetail must be declared explicitly even though it subclasses
    # MessageSummary — otherwise its inherited PHI ``summary``/``error`` would be returned un-gated.
    # Gated on view_summary (NOT view_raw) so the same logical fields (error / last_error / detail)
    # sit on one tier across the list and detail surfaces; the detail route already requires view_raw,
    # so a view_raw gate here would be dead code. The raw body stays on the route's view_raw gate.
    MessageDetail: {
        "summary": Permission.MESSAGES_VIEW_SUMMARY,
        "error": Permission.MESSAGES_VIEW_SUMMARY,
    },
    OutboxInfo: {
        "last_error": Permission.MESSAGES_VIEW_SUMMARY,
    },
    EventInfo: {
        "detail": Permission.MESSAGES_VIEW_SUMMARY,
    },
    CapturedResponseInfo: {
        "detail": Permission.MESSAGES_VIEW_SUMMARY,
    },
}

M = TypeVar("M", bound=BaseModel)


def gated_properties(model_cls: type[BaseModel]) -> dict[str, Permission]:
    """The PHI property→permission map declared for ``model_cls`` (empty if it has none)."""
    return PHI_FIELDS.get(model_cls, {})


def redact_unauthorized(model: M, identity: Identity) -> M:
    """Return ``model`` with each PHI property the caller may **not** see set to ``None`` — a no-op
    when the caller holds every relevant permission. The single per-property read gate (ASVS 8.2.3)."""
    withheld = {
        prop: None for prop, perm in gated_properties(type(model)).items() if not identity.has(perm)
    }
    return model.model_copy(update=withheld) if withheld else model


def count_exposed(models: Sequence[BaseModel]) -> int:
    """How many ``models`` still carry a non-empty PHI property — call **after** redaction, so the
    count reflects what is actually returned. Fed to the server-side PHI-exposure audit."""
    return sum(
        1 for m in models if any(getattr(m, prop, None) for prop in gated_properties(type(m)))
    )
