# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Centralized field-level (property) authorization (WP-9, ASVS 8.1.2/8.2.3).

The PHI map + `redact_unauthorized` are the single place per-property read gating happens; these tests
pin the behavior (holder sees / non-holder redacted), the exposure count, and the map's integrity."""

from __future__ import annotations

from typing import Any

from messagefoundry.api.field_authz import (
    PHI_FIELDS,
    count_exposed,
    gated_properties,
    redact_unauthorized,
)
from messagefoundry.api.models import (
    CapturedResponseInfo,
    DeadLetterRow,
    EventInfo,
    MessageDetail,
    MessageSummary,
    OutboxInfo,
    ReplayResult,
)
from messagefoundry.auth import Identity, Permission
from messagefoundry.auth.identity import AuthProvider


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
        status="ERROR",
        error="boom in PID-5",
        summary="DOE^JOHN",
    )
    base.update(over)
    return MessageSummary(**base)


def _dead(**over: Any) -> DeadLetterRow:
    base: dict[str, Any] = dict(  # noqa: C408
        outbox_id="o1",
        message_id="m1",
        channel_id="IB",
        destination_name="OB",
        attempts=3,
        last_error="delivery failed: 9f3c",
        failed_at=0.0,
        control_id="c1",
        message_type="ADT^A01",
        received_at=0.0,
        summary="DOE^JOHN",
    )
    base.update(over)
    return DeadLetterRow(**base)


def test_holder_sees_summary_masked_until_revealed() -> None:
    """Permission is not reveal (ASVS 14.2.6): a holder gets the summary MASKED by default.

    ``error`` is not in ``MASKED_UNTIL_REVEALED``, so it is unchanged in the same call — which is
    what makes this a test of the mask rather than of redaction.
    """
    m = redact_unauthorized(_summary(), _identity(Permission.MESSAGES_VIEW_SUMMARY))
    assert m.summary == "****" and m.error == "boom in PID-5"


def test_holder_sees_complete_summary_only_on_a_reveal() -> None:
    m = redact_unauthorized(
        _summary(), _identity(Permission.MESSAGES_VIEW_SUMMARY), revealed=frozenset({"summary"})
    )
    assert m.summary == "DOE^JOHN"


def test_reveal_without_permission_still_denies() -> None:
    """Reveal is not a second route to the value -- it only lifts the mask on what permission allows.

    Asking for a reveal you have no permission for must return ``None``, not the complete value and
    not a mask of it. Masking a value the caller may not see at all would leak its shape.
    """
    m = redact_unauthorized(
        _summary(), _identity(Permission.MESSAGES_READ), revealed=frozenset({"summary"})
    )
    assert m.summary is None


def test_a_reveal_does_not_persist_to_the_next_message() -> None:
    """The reveal is an ACT on one record, never a STATUS that renders the next one.

    This is the sticky anti-pattern arriving by accident, and it passes any test that checks a
    single message. Revealing message one and then redacting message two with the SAME identity
    must leave message two masked.
    """
    holder = _identity(Permission.MESSAGES_VIEW_SUMMARY)
    first = redact_unauthorized(_summary(id="m1"), holder, revealed=frozenset({"summary"}))
    second = redact_unauthorized(_summary(id="m2"), holder)  # no reveal for this one

    assert first.summary == "DOE^JOHN"  # positive control: the reveal did work on m1
    assert second.summary == "****"  # and did not survive into m2


def test_reveal_cannot_be_held_anywhere_but_the_call() -> None:
    """Structural, not behavioural: ``revealed`` is a keyword-only parameter with no stored
    counterpart, so a reveal cannot outlive the call. A future refactor that parks it on the
    identity, the module or a default would break this signature check first."""
    import inspect

    param = inspect.signature(redact_unauthorized).parameters["revealed"]
    assert param.kind is inspect.Parameter.KEYWORD_ONLY
    assert param.default == frozenset()  # the default is "nothing revealed", not "remember"


def test_non_holder_has_phi_fields_nulled_others_untouched() -> None:
    m = redact_unauthorized(
        _summary(), _identity(Permission.MESSAGES_READ)
    )  # read, not view_summary
    assert m.summary is None and m.error is None
    # Non-PHI properties are never touched.
    assert m.control_id == "c1" and m.status == "ERROR" and m.message_type == "ADT^A01"


def test_dead_letter_summary_and_last_error_gated() -> None:
    holder = redact_unauthorized(_dead(), _identity(Permission.MESSAGES_VIEW_SUMMARY))
    # summary is masked until revealed; last_error is not a masked property, so it is unchanged.
    assert holder.summary == "****" and holder.last_error == "delivery failed: 9f3c"
    redacted = redact_unauthorized(_dead(), _identity())
    assert redacted.summary is None and redacted.last_error is None


def test_count_exposed_reflects_what_is_returned() -> None:
    holder, nonholder = _identity(Permission.MESSAGES_VIEW_SUMMARY), _identity()
    rows = [_summary(), _summary(summary=None, error=None)]  # one carries PHI, one already blank
    assert count_exposed([redact_unauthorized(r, holder) for r in rows]) == 1
    assert count_exposed([redact_unauthorized(r, nonholder) for r in rows]) == 0


def test_unmapped_model_is_passthrough() -> None:
    # A model with no PHI map entry is never redacted and counts zero exposed. (ReplayResult has no
    # PHI fields; OutboxInfo IS mapped now — #120 — so it is no longer a valid passthrough example.)
    assert gated_properties(ReplayResult) == {}
    row = ReplayResult(message_id="m1", requeued=2)
    assert redact_unauthorized(row, _identity()) is row
    assert count_exposed([row]) == 0


def test_detail_and_nested_rows_gated() -> None:
    # #120: the detail wrapper AND each nested OutboxInfo/EventInfo are gated individually (redaction
    # keys on the exact type, so MessageDetail's inherited summary/error must still be gated, and the
    # nested rows are redacted one-by-one — not recursively via the wrapper).
    detail = MessageDetail(
        id="m1",
        channel_id="IB",
        received_at=0.0,
        source_type="mllp",
        control_id="c1",
        message_type="ADT^A01",
        status="ERROR",
        error="boom in PID-5",
        summary="DOE^JOHN",
        raw="MSH|^~\\&|...",
        outbox=[
            OutboxInfo(
                id="o1",
                destination_name="OB",
                status="DEAD",
                attempts=3,
                next_attempt_at=0.0,
                last_error="bad MRN",
            )
        ],
        events=[EventInfo(ts=0.0, event="error", destination=None, detail="PID-5 invalid")],
    )
    nonholder = _identity(
        Permission.MESSAGES_READ
    )  # reaches the detail route but lacks view_summary
    assert redact_unauthorized(detail, nonholder).summary is None
    assert redact_unauthorized(detail, nonholder).error is None
    assert redact_unauthorized(detail.outbox[0], nonholder).last_error is None
    assert redact_unauthorized(detail.events[0], nonholder).detail is None
    holder = _identity(Permission.MESSAGES_VIEW_SUMMARY)
    assert redact_unauthorized(detail, holder).error == "boom in PID-5"
    assert redact_unauthorized(detail.outbox[0], holder).last_error == "bad MRN"
    assert redact_unauthorized(detail.events[0], holder).detail == "PID-5 invalid"


def test_mapped_properties_exist_on_their_models() -> None:
    # Catches a typo'd/renamed field in the map.
    for model_cls, props in PHI_FIELDS.items():
        for prop in props:
            assert prop in model_cls.model_fields, f"{model_cls.__name__}.{prop}"


def test_known_phi_fields_are_mapped() -> None:
    # Change-detector: if a new PHI-bearing response property is added, it must be added to PHI_FIELDS
    # (and this expectation) — otherwise it would be returned ungated.
    assert set(gated_properties(MessageSummary)) == {"summary", "error", "metadata"}
    assert set(gated_properties(DeadLetterRow)) == {"summary", "last_error"}
    assert set(gated_properties(MessageDetail)) == {"summary", "error", "metadata"}
    assert set(gated_properties(OutboxInfo)) == {"last_error"}
    assert set(gated_properties(EventInfo)) == {"detail"}
    assert set(gated_properties(CapturedResponseInfo)) == {"detail"}
