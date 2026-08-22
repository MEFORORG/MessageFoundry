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

**The default denies.** The models here are :class:`~messagefoundry.api.phi_gate.PhiGatedModel`\\ s,
which withhold every gated property from JSON until an authorization decision is recorded on the
instance; :func:`redact_unauthorized` is what records one. That module states the mechanism and its
scope — this one owns the policy (which permission unlocks which property).

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
from messagefoundry.api.phi_gate import PhiGatedModel
from messagefoundry.auth import Identity, Permission

#: Response model → {property → Permission that unlocks it}. The single source of truth for which
#: response properties are PHI-gated and by which permission; :func:`redact_unauthorized` nulls a
#: property when the caller lacks its permission. All three summary-tier PHI fields
#: (``summary`` / ``error`` / ``metadata``) gate on ``messages:view_summary`` today (the body, gated
#: by ``messages:view_raw``, is handled at the endpoint). ``metadata`` is an EF-3 cipher-encrypted,
#: PHI-classified column (carrying re-ingress/correlation lineage today, operator/handler-attached
#: values by design) — so it must be gated and audited like the other summary-tier PHI fields, not
#: returned to a caller lacking view_summary. Add a row here when a new PHI-bearing response property
#: is introduced — and name it in the model's own ``phi_gated_properties`` in the same change, which
#: ``tests/test_field_authz_fail_closed.py`` pins in both directions.
PHI_FIELDS: dict[type[BaseModel], dict[str, Permission]] = {
    MessageSummary: {
        "summary": Permission.MESSAGES_VIEW_SUMMARY,
        "error": Permission.MESSAGES_VIEW_SUMMARY,
        "metadata": Permission.MESSAGES_VIEW_SUMMARY,
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
        "metadata": Permission.MESSAGES_VIEW_SUMMARY,
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

#: Properties whose *authorized* value is still display-masked until a reveal act (ASVS 14.2.6).
#: Authorization and reveal are two different decisions: permission says the caller MAY see the
#: value, a reveal says they asked for THIS one. Only ``summary`` today, which is the subject that
#: was allocated.
#:
#: **``metadata`` carries the same ingest-derived MRN/patient-name PHI** (see ``PHI_FIELDS`` above)
#: and is the obvious next candidate — named here rather than silently included or silently left
#: out, because masking one field while the same identifiers return complete one field over is a
#: partial control that reads as a whole one.
MASKED_UNTIL_REVEALED: frozenset[str] = frozenset({"summary"})

#: What a masked run is replaced with. ASCII on purpose (the no-glyph rule), and a fixed width so
#: the mask never leaks the length of what it hides.
_MASK = "****"

#: How many trailing characters of an identifier survive the mask. Four is enough to confirm a
#: record you already identified and not enough to read a census off a screen opened for another
#: reason — which is precisely the exposure 14.2.6 describes, and the one the triage objection was
#: measured against (search matches inside the store, before redaction, so finding a known patient
#: is unaffected).
_KEEP_TAIL = 4

M = TypeVar("M", bound=BaseModel)


def mask_for_display(summary: str) -> str:
    """Mask the identifiers in a composed summary, keeping it recognizable but not enumerable.

    ``MRN 100001 · DOE, JANE`` becomes ``MRN ****0001 · D**, J**``. The separator, the labels and
    the shape survive so the row still reads as a row; the values do not.

    Structure comes from :func:`messagefoundry.parsing.summary.summarize` — parts joined by
    ``" · "``, each either ``<label> <value>`` for an identifier or a bare ``FAMILY, GIVEN``
    name. An unrecognized part is masked whole rather than passed through: an unknown shape is the
    case where guessing wrong leaks, so the default is to hide it.
    """
    if not summary:
        return summary
    return " · ".join(_mask_part(p) for p in summary.split(" · "))


def _mask_part(part: str) -> str:
    label, sep, value = part.partition(" ")
    if sep and label in _IDENTIFIER_LABELS:
        return f"{label} {_mask_tail(value)}"
    if "," in part:  # FAMILY, GIVEN -- keep each initial so the row stays scannable
        return ", ".join(_mask_name(n.strip()) for n in part.split(","))
    return _MASK


def _mask_tail(value: str) -> str:
    """Keep the last :data:`_KEEP_TAIL` characters; mask the rest at fixed width."""
    return f"{_MASK}{value[-_KEEP_TAIL:]}" if len(value) > _KEEP_TAIL else _MASK


def _mask_name(name: str) -> str:
    """Keep one initial. An empty component stays empty rather than becoming a bare mask."""
    return f"{name[0]}{_MASK[:2]}" if name else name


#: Labels :func:`~messagefoundry.parsing.summary.summarize` puts in front of an identifier value.
#: Kept beside the masker so the two move together; a label added there and not here degrades to
#: the whole-part mask, which is the safe direction.
_IDENTIFIER_LABELS = frozenset({"MRN", "Order", "Acc"})


def gated_properties(model_cls: type[BaseModel]) -> dict[str, Permission]:
    """The PHI property→permission map declared for ``model_cls`` (empty if it has none)."""
    return PHI_FIELDS.get(model_cls, {})


def redact_unauthorized(  # noqa: UP047
    model: M,
    identity: Identity,
    *,
    revealed: frozenset[str] = frozenset(),
) -> M:
    """Return ``model`` with each PHI property the caller may **not** see set to ``None``, and the
    rest **released** for serialization. The single per-property read gate (ASVS 8.2.3).

    Release is the half that makes the gate fail-closed (#1045): a :class:`PhiGatedModel` withholds
    every gated property from JSON until an authorization decision is recorded on the instance, so
    this call is what turns a permitted property back on rather than what turns a forbidden one off.
    A route that never calls it returns ``null`` for all of them.

    **Authorization is not reveal (ASVS 14.2.6).** A permitted property in
    :data:`MASKED_UNTIL_REVEALED` is display-masked unless this call names it in ``revealed``. That
    is two decisions, not one: the permission says the caller MAY see such values, the reveal says
    they asked for THIS record's.

    ``revealed`` is a **per-call argument with no stored counterpart anywhere** — deliberately, and
    it is the whole design. A reveal held on the session, the identity or the module would be a
    *status* rather than an *act*, which renders every row on screen for as long as it is set. Being
    a parameter, it cannot outlive the call that passed it, so the leak is impossible by
    construction rather than prevented by review.
    """
    gated = gated_properties(type(model))
    if not gated:
        return model
    allowed = {prop for prop, perm in gated.items() if identity.has(perm)}
    # Still null the values, so `count_exposed` and any server-side read of the returned model agree
    # with what is actually serialized. The serializer alone would leave the attribute populated.
    withheld: dict[str, object | None] = {prop: None for prop in gated if prop not in allowed}
    for prop in allowed & MASKED_UNTIL_REVEALED - revealed:
        value = getattr(model, prop, None)
        if isinstance(value, str) and value:
            withheld[prop] = mask_for_display(value)
    out = model.model_copy(update=withheld)
    if isinstance(out, PhiGatedModel):
        out.release_phi(allowed)
    return out


def count_exposed(models: Sequence[BaseModel]) -> int:
    """How many ``models`` still carry a non-empty PHI property — call **after** redaction, so the
    count reflects what is actually returned. Fed to the server-side PHI-exposure audit."""
    return sum(
        1 for m in models if any(getattr(m, prop, None) for prop in gated_properties(type(m)))
    )
