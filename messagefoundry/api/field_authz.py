# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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

The full message **body** (``MessageBody.raw``, from ``GET /messages/{id}/raw``) is governed separately,
at the endpoint, by the coarser whole-body ``messages:view_raw`` gate — not by this per-property map.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from types import MappingProxyType
from typing import TypeVar

from pydantic import BaseModel

from messagefoundry.api.models import (
    AlertInstanceInfo,
    CapturedResponseInfo,
    ConnectionEventInfo,
    ConnectionRow,
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
    # The connection event log and the alert list (BACKLOG #2443). The event routes need only
    # ``monitoring:read``, which the built-in Viewer, Deployment, Coding and Auditor roles hold
    # without any PHI permission. The alert route needs ``monitoring:diagnose``, which only the
    # built-in Operator and Administrator hold, and both also hold ``messages:view_summary``; a
    # custom role may hold ``monitoring:diagnose`` without it. So the reason is gated here on the
    # same tier as ``messages.error``: the same ``safe_exc`` text reaches ``connection_event.reason``
    # and ``alert_instance.reason``.
    ConnectionEventInfo: {
        "reason": Permission.MESSAGES_VIEW_SUMMARY,
    },
    AlertInstanceInfo: {
        "reason": Permission.MESSAGES_VIEW_SUMMARY,
    },
    # The connections dashboard row (BACKLOG #2443, step 4). ``GET /connections`` needs only
    # ``monitoring:read``, and ``error`` is why a connection failed to start: the same ``safe_exc``
    # text whose stored copy is an alert reason. ``ConnectionMetadata.error`` carries the same
    # string and is NOT mapped yet; docs/SECURITY.md "Field-level (property) authorization" says why.
    ConnectionRow: {
        "error": Permission.MESSAGES_VIEW_SUMMARY,
    },
}

#: Properties whose *authorized* value is still display-masked until a reveal act (ASVS 14.2.6).
#: Authorization and reveal are two different decisions: permission says the caller MAY see the
#: value, a reveal says they asked for THIS one.
#:
#: **``metadata`` joined ``summary`` here under BACKLOG #1187.** This comment used to name it
#: "the obvious next candidate" and leave it out, on the stated grounds that masking one field
#: while the same identifiers return complete one field over is a partial control that reads as
#: a whole one. That was an accurate description of the gap, so the gap is closed rather than
#: re-described: ``PHI_FIELDS`` above rates ``metadata`` on the same view_summary tier for the
#: same ingest-derived MRN/patient-name reason, and every list surface returned it complete on
#: each row while ``summary`` beside it was masked.
#:
#: ``mask_for_display`` reads the composed-summary grammar, which ``metadata`` does not follow --
#: its values are code- and operator-attached and its mechanism is still TBD. That is handled
#: rather than overlooked: an unrecognized part is masked WHOLE, so an unknown shape degrades to
#: the fixed-width mask rather than being passed through. Fail-closed is the right direction for
#: a field whose grammar is not yet fixed, and the detail route's reveal still returns it whole.
MASKED_UNTIL_REVEALED: frozenset[str] = frozenset({"summary", "metadata"})

#: Free-text error-tier properties, masked WHOLE until their own reveal act (BACKLOG #2436, ASVS
#: 14.2.6, owner ruling R12). The engine scrubs these strings, and the scrubber is not
#: de-identification: an identifier it missed would show on a page opened to check a delivery.
#:
#: **Keyed by model, not by property name, unlike** :data:`MASKED_UNTIL_REVEALED`. By name,
#: ``detail`` would also catch ``CapturedResponseInfo.detail`` on ``/responses``, a different datum
#: (the partner's reply note) with no reveal act of its own, so it is left out on purpose.
#:
#: The list rows are IN, although they have no reveal of their own. ``MessageSummary.error`` on the
#: message list and search is the same stored ``messages.error`` as ``MessageDetail.error``, and a
#: ``DeadLetterRow`` is one of the message's outbox rows. Left complete there, a bulk list would hand
#: out exactly the text the open masks, so the per-message reveal would guard nothing. Each is
#: revealed by opening its message with the error-text act, one audited request per message.
#:
#: Masked whole with :data:`_MASK`, never through :func:`mask_for_display`. That function reads the
#: composed-summary grammar, so free text with a comma in it would come back as initials.
ERROR_TEXT_MASKED_UNTIL_REVEALED: Mapping[type[BaseModel], frozenset[str]] = MappingProxyType(
    {
        MessageSummary: frozenset({"error"}),
        MessageDetail: frozenset({"error"}),
        OutboxInfo: frozenset({"last_error"}),
        EventInfo: frozenset({"detail"}),
        DeadLetterRow: frozenset({"last_error"}),
        # BACKLOG #2443: the same delivery-error text, copied into a ``connection_lost`` event and
        # its ``connection_error`` alert. Each is revealed by its own per-item act, the ``reveal``
        # id on its list route, one audited request per event or alert.
        ConnectionEventInfo: frozenset({"reason"}),
        AlertInstanceInfo: frozenset({"reason"}),
        # BACKLOG #2443 step 4: why a connection failed to start or was DR-parked. Revealed by the
        # ``reveal=<connection name>`` act on ``GET /connections``, one audited request per name.
        ConnectionRow: frozenset({"error"}),
    }
)


def revealable(model_cls: type[BaseModel], *, summary: bool, error_text: bool) -> frozenset[str]:
    """The masked properties of ``model_cls`` that the caller's explicit acts lift, for one call.

    ``summary`` is the summary reveal (BACKLOG #2346); ``error_text`` is the error-tier reveal
    (BACKLOG #2436). They are separate acts, so each lifts only its own set. Built here from the
    two tables rather than spelled at a call site, so a property added to either table for a model
    the detail route redacts is revealed by its act without a second edit. That is not true of a
    LIST model: nothing passes a reveal for ``MessageSummary`` or ``DeadLetterRow``, whose text is
    revealed by opening the message. A new list row added to a table needs that path too. Only
    properties the model actually gates are returned, so every name is readable on an instance."""
    out: frozenset[str] = MASKED_UNTIL_REVEALED if summary else frozenset()
    if error_text:
        out |= ERROR_TEXT_MASKED_UNTIL_REVEALED.get(model_cls, frozenset())
    return out.intersection(gated_properties(model_cls))


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
    :data:`MASKED_UNTIL_REVEALED`, or in this model's row of
    :data:`ERROR_TEXT_MASKED_UNTIL_REVEALED`, is display-masked unless this call names it in
    ``revealed``; :func:`revealable` builds that set from the caller's acts. That
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
    masked: set[str] = set()
    error_text = ERROR_TEXT_MASKED_UNTIL_REVEALED.get(type(model), frozenset())
    for prop in allowed & ((MASKED_UNTIL_REVEALED | error_text) - revealed):
        value = getattr(model, prop, None)
        if isinstance(value, str) and value:
            # Free error text has no grammar to keep, so it is hidden whole (BACKLOG #2436).
            withheld[prop] = _MASK if prop in error_text else mask_for_display(value)
            masked.add(prop)
    out = model.model_copy(update=withheld)
    if isinstance(out, PhiGatedModel):
        out.release_phi(allowed)
        # Only properties actually replaced with a mask -- an empty value is not masked, it is
        # empty, and marking it would make `count_exposed` skip a property that later becomes real.
        out.mark_phi_masked(masked)
    return out


def count_exposed(models: Sequence[BaseModel]) -> int:
    """How many ``models`` still carry a READABLE PHI property — call **after** redaction, so the
    count reflects what is actually returned. Fed to the server-side PHI-exposure audit.

    A **display-masked** property is not an exposure and is not counted (ASVS 14.2.6). It is
    non-empty, so counting on emptiness alone would report a PHI exposure for every masked list row
    and bury the record someone actually opened. The mask is read from the model's own record of
    what it masked, never inferred from the value -- a real summary may contain the mask characters.
    """

    return sum(1 for m in models if _has_readable_phi(m))


def count_masked(models: Sequence[BaseModel]) -> int:
    """How many ``models`` carry a display-masked PHI property and nothing readable.

    The other half of the exposure audit. A masked row is not a disclosure, but it is still a row
    someone asked for -- so a bulk list fetch has to stay visible in the audit even though it
    harvested no identifiers. Counting only :func:`count_exposed` would make a 5,000-row scrape
    indistinguishable from no request at all, which is the harvest signal the audit exists to keep.
    """
    return sum(
        1
        for m in models
        if not _has_readable_phi(m)
        and isinstance(m, PhiGatedModel)
        and any(getattr(m, p, None) for p in m._phi_masked)
    )


def _has_readable_phi(m: BaseModel) -> bool:
    """True when any gated property is non-empty AND not display-masked."""
    masked = m._phi_masked if isinstance(m, PhiGatedModel) else frozenset()
    return any(getattr(m, p, None) for p in gated_properties(type(m)) if p not in masked)
