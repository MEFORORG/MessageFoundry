# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Regression for SEC-006 (CWE-213): the PHI-classified ``metadata`` message property is gated by the
field-level authorization map exactly like ``summary``/``error``.

``messages.metadata`` is an EF-3 cipher-encrypted, PHI-classified column (it carries re-ingress /
correlation lineage today, operator/handler-attached values by design). Before this fix it was absent
from :data:`PHI_FIELDS`, so a caller lacking ``messages:view_summary`` received it un-redacted and its
exposure was never fed to the PHI-exposure audit coalescer. These tests pin that ``metadata`` is now
nulled for a non-holder, audited via ``count_exposed`` when populated AND revealed, and that the map
cannot silently drift away from the model (drift-guard).

**Updated under BACKLOG #1187 (ASVS 14.2.6), and the distinction matters.** ``metadata`` joined
``summary`` in ``MASKED_UNTIL_REVEALED``, so an authorized holder now sees it DISPLAY-MASKED unless
the call names it in ``revealed``. That is a second decision on top of the one this file grades:
authorization says the caller MAY see such values, the reveal says they asked for THIS record's.
Every holder assertion below therefore passes ``revealed`` -- these are positive controls proving the
GATE releases, and a masked value would leave them unable to tell a working gate from a working mask.
The non-holder assertions are untouched, because masking changes nothing for a caller who was never
authorized: they still get ``None``."""

from __future__ import annotations

from typing import Any

from messagefoundry.api.field_authz import (
    PHI_FIELDS,
    count_exposed,
    gated_properties,
    redact_unauthorized,
)
from messagefoundry.api.models import MessageDetail, MessageSummary
from messagefoundry.auth import Identity, Permission
from messagefoundry.auth.identity import AuthProvider

# A non-null metadata value mirroring the ADR-0013 re-ingress/correlation lineage blob.
METADATA_JSON = '{"correlation_id":"c1","root_id":"r1","depth":1,"reingress_of_seq":7}'


def _identity(*perms: Permission) -> Identity:
    return Identity(
        user_id="1",
        username="u",
        auth_provider=AuthProvider.LOCAL,
        roles=frozenset(),
        permissions=frozenset(perms),
    )


def _summary(**over: Any) -> MessageSummary:
    base: dict[str, Any] = dict(  # noqa: C408
        id="m1",
        channel_id="IB",
        received_at=0.0,
        source_type="mllp",
        control_id="c1",
        message_type="ADT^A01",
        status="PROCESSED",
        error=None,
        summary=None,
        metadata=METADATA_JSON,
    )
    base.update(over)
    return MessageSummary(**base)


def _detail(**over: Any) -> MessageDetail:
    base: dict[str, Any] = dict(  # noqa: C408
        id="m1",
        channel_id="IB",
        received_at=0.0,
        source_type="mllp",
        control_id="c1",
        message_type="ADT^A01",
        status="PROCESSED",
        error=None,
        summary=None,
        metadata=METADATA_JSON,
        raw="MSH|^~\\&|...",
        outbox=[],
        events=[],
    )
    base.update(over)
    return MessageDetail(**base)


def test_metadata_nulled_for_non_view_summary_holder_on_summary() -> None:
    # A Viewer (messages:read, no view_summary) must NOT see the decrypted metadata.
    m = redact_unauthorized(_summary(), _identity(Permission.MESSAGES_READ))
    assert m.metadata is None
    # Holder still sees it. The reveal is passed because this control is about the GATE: without it
    # the value comes back masked, which is also non-None, and the assertion would stop
    # distinguishing "the gate released" from "the mask ran".
    held = redact_unauthorized(
        _summary(),
        _identity(Permission.MESSAGES_VIEW_SUMMARY),
        revealed=frozenset({"metadata"}),
    )
    assert held.metadata == METADATA_JSON
    # The masked state is a THIRD outcome, distinct from both released and withheld. Asserted here so
    # dropping metadata from MASKED_UNTIL_REVEALED reds this file rather than passing quietly.
    masked = redact_unauthorized(_summary(), _identity(Permission.MESSAGES_VIEW_SUMMARY))
    assert masked.metadata is not None, "masked is not withheld"
    assert masked.metadata != METADATA_JSON, "an unrevealed read returned the complete value"


def test_metadata_nulled_for_non_view_summary_holder_on_detail() -> None:
    nonholder = _identity(Permission.MESSAGES_READ)  # reaches the detail route, lacks view_summary
    assert redact_unauthorized(_detail(), nonholder).metadata is None
    holder = _identity(Permission.MESSAGES_VIEW_SUMMARY)
    revealed = redact_unauthorized(_detail(), holder, revealed=frozenset({"metadata"}))
    assert revealed.metadata == METADATA_JSON


def test_count_exposed_counts_metadata_only_phi() -> None:
    # A row whose ONLY non-null PHI field is metadata must count as exposed when it is actually shown
    # complete, and zero for a non-holder — proving metadata feeds the exposure audit.
    #
    # BACKLOG #1187 added a third case between those two, and it is the one worth stating: a holder
    # who did NOT reveal sees a mask, and a mask is NOT an exposure. count_exposed skips masked
    # properties by design (mark_phi_masked), which is what makes the counter mean "PHI actually put
    # on screen" rather than "PHI the caller could have asked for". metadata now behaves exactly as
    # summary already did.
    holder, nonholder = (
        _identity(Permission.MESSAGES_VIEW_SUMMARY),
        _identity(Permission.MESSAGES_READ),
    )
    rows = [_summary()]  # summary/error None, metadata populated
    revealed = [redact_unauthorized(r, holder, revealed=frozenset({"metadata"})) for r in rows]
    assert count_exposed(revealed) == 1, "a revealed, complete metadata value must count as exposed"
    assert count_exposed([redact_unauthorized(r, nonholder) for r in rows]) == 0
    assert count_exposed([redact_unauthorized(r, holder) for r in rows]) == 0, (
        "a MASKED metadata value counted as an exposure; the counter would then over-report every "
        "list surface, and an operator reading the PHI-exposure audit could not tell a page of masks "
        "from a page of identifiers"
    )


def test_metadata_is_gated_and_map_does_not_drift() -> None:
    # Drift-guard: metadata must be present in both message-tier entries and gated on view_summary,
    # and every mapped property must be an actual field of its model so the EF-3/PHI column and the
    # field-authz map cannot silently diverge.
    assert PHI_FIELDS[MessageSummary]["metadata"] is Permission.MESSAGES_VIEW_SUMMARY
    assert PHI_FIELDS[MessageDetail]["metadata"] is Permission.MESSAGES_VIEW_SUMMARY
    for model_cls, props in PHI_FIELDS.items():
        for prop in props:
            assert prop in model_cls.model_fields, f"{model_cls.__name__}.{prop}"
    assert "metadata" in gated_properties(MessageSummary)
    assert "metadata" in gated_properties(MessageDetail)
