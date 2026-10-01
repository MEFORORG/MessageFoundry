# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Centralized field-level (property) authorization (WP-9, ASVS 8.1.2/8.2.3).

The PHI map + `redact_unauthorized` are the single place per-property read gating happens; these tests
pin the behavior (holder sees / non-holder redacted), the exposure count, and the map's integrity."""

from __future__ import annotations

from typing import Any

from messagefoundry.api.field_authz import (
    ERROR_TEXT_MASKED_UNTIL_REVEALED,
    MASKED_UNTIL_REVEALED,
    PHI_FIELDS,
    count_exposed,
    gated_properties,
    redact_unauthorized,
    revealable,
)
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

    The same call with ``error`` revealed returns it complete, which is what makes this a test of
    the mask rather than of redaction: the caller may read the row, and asked for only the error.
    """
    holder = _identity(Permission.MESSAGES_VIEW_SUMMARY)
    m = redact_unauthorized(_summary(), holder, revealed=frozenset({"error"}))
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
    # Both are masked until revealed: summary by its grammar, last_error whole (BACKLOG #2436).
    assert holder.summary == "****" and holder.last_error == "****"
    redacted = redact_unauthorized(_dead(), _identity())
    assert redacted.summary is None and redacted.last_error is None


def test_a_masked_value_is_not_counted_as_a_phi_exposure() -> None:
    """The exposure audit must count what the caller could READ, not what the field was called.

    Masking (ASVS 14.2.6) made every list row carry a non-empty ``summary`` again -- ``MRN ****0001``
    is truthy -- so a counter keyed on "is this property non-empty" reports a PHI exposure for a row
    whose identifiers were never shown. At list scale that is a false positive per row, and it
    drowns the signal the audit exists for: the single record someone actually opened.
    """
    holder = _identity(Permission.MESSAGES_VIEW_SUMMARY)
    # Only the masked property is populated, so nothing else can account for a count.
    masked = redact_unauthorized(_summary(error=None, metadata=None), holder)
    assert masked.summary == "****"  # populated, and unreadable
    assert count_exposed([masked]) == 0

    revealed = redact_unauthorized(
        _summary(error=None, metadata=None), holder, revealed=frozenset({"summary"})
    )
    assert revealed.summary == "DOE^JOHN"
    assert count_exposed([revealed]) == 1  # the control: the same row, actually exposed


def test_a_masked_row_still_counts_when_another_phi_property_is_complete() -> None:
    """Masking one property must not suppress the count for a different one that IS readable.

    A row whose summary is masked and whose error was revealed is still an exposure -- and a fix
    that keyed on "this model has any masked property" rather than on the individual values would
    have hidden it.
    """
    holder = _identity(Permission.MESSAGES_VIEW_SUMMARY)
    row = redact_unauthorized(_summary(metadata=None), holder, revealed=frozenset({"error"}))
    assert row.summary == "****" and row.error == "boom in PID-5"
    assert count_exposed([row]) == 1


def test_count_exposed_reflects_what_is_returned() -> None:
    holder, nonholder = _identity(Permission.MESSAGES_VIEW_SUMMARY), _identity()
    rows = [_summary(), _summary(summary=None, error=None)]  # one carries PHI, one already blank
    shown = revealable(MessageSummary, summary=True, error_text=True)
    assert count_exposed([redact_unauthorized(r, holder, revealed=shown) for r in rows]) == 1
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
    # A holder gets each error-tier value masked until the reveal act (BACKLOG #2436) ...
    assert redact_unauthorized(detail, holder).error == "****"
    assert redact_unauthorized(detail.outbox[0], holder).last_error == "****"
    assert redact_unauthorized(detail.events[0], holder).detail == "****"
    # ... and whole on it.
    shown = revealable(MessageDetail, summary=False, error_text=True)
    assert redact_unauthorized(detail, holder, revealed=shown).error == "boom in PID-5"
    shown = revealable(OutboxInfo, summary=False, error_text=True)
    assert redact_unauthorized(detail.outbox[0], holder, revealed=shown).last_error == "bad MRN"
    shown = revealable(EventInfo, summary=False, error_text=True)
    assert redact_unauthorized(detail.events[0], holder, revealed=shown).detail == "PID-5 invalid"


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


# --- metadata is masked until revealed (BACKLOG #1187, ASVS 14.2.6) -----------------------------


def test_metadata_is_masked_on_a_list_surface_and_complete_on_a_reveal() -> None:
    """``metadata`` is display-masked like ``summary``, not returned complete beside a masked field.

    ``PHI_FIELDS`` rates ``metadata`` on the same view_summary tier as ``summary``, for the same
    reason: it carries ingest-derived MRN and patient-name PHI. Before BACKLOG #1187 only ``summary``
    was in ``MASKED_UNTIL_REVEALED``, so a list surface masked one field while returning the same
    class of identifier complete one field over -- a partial control that reads as a whole one, which
    is what ``field_authz.py``'s own comment called it.

    The reveal is the control, and it is the half that matters: this must be a MASK, not a
    withholding. A caller who deliberately opens one record still gets the complete value, which is
    what keeps the console able to do its job.
    """
    holder = _identity(Permission.MESSAGES_VIEW_SUMMARY)
    meta = "MRN 100001"

    listed = redact_unauthorized(_summary(metadata=meta), holder)
    assert listed.metadata is not None, "masked is not withheld -- a mask must still return a value"
    assert listed.metadata != meta, "metadata came back complete on a surface that revealed nothing"

    revealed = redact_unauthorized(
        _summary(metadata=meta), holder, revealed=frozenset({"summary", "metadata"})
    )
    assert revealed.metadata == meta, "a deliberate reveal must return the complete value"


def test_metadata_with_an_unknown_grammar_fails_closed() -> None:
    """``mask_for_display`` reads the composed-summary grammar; ``metadata`` need not follow it.

    Its values are code- and operator-attached and its mechanism is documented as TBD, so the mask
    must not pass an unrecognized shape through. It degrades to the whole-part mask instead. This is
    asserted rather than left to the summary tests, because it is the case that decides whether
    extending the mask set to ``metadata`` is safe at all.
    """
    holder = _identity(Permission.MESSAGES_VIEW_SUMMARY)
    blob = '{"user": {"note": "MRN 100001 attached by a handler"}}'
    masked = redact_unauthorized(_summary(metadata=blob), holder).metadata
    assert masked is not None and "100001" not in masked, (
        f"an unrecognized metadata shape leaked an identifier through the mask: {masked!r}"
    )


def test_the_reveal_set_on_the_detail_route_covers_every_masked_property() -> None:
    """Every reveal call site must reveal every masked property, or a field silently stays masked.

    Adding a property to ``MASKED_UNTIL_REVEALED`` or ``ERROR_TEXT_MASKED_UNTIL_REVEALED`` and
    forgetting the reveal would mask it everywhere with no way to see it -- a product break that no
    masking test would catch, because masking is what every other test asserts. Since BACKLOG #2436
    the detail route builds each model's set with ``revealable`` behind the two explicit acts, so
    the tables and the route cannot drift. This pins that every site still does, that the sites
    are exactly the three models the route redacts, and that no other reveal site has appeared.
    Read from the source rather than restated.
    """
    import pathlib
    import re

    app_py = pathlib.Path(__file__).resolve().parents[1] / "messagefoundry" / "api" / "app.py"
    source = app_py.read_text(encoding="utf-8")
    # The one place the sets are built: revealable() behind BOTH acts, over the three models.
    built = re.findall(
        r"cls: revealable\(cls, summary=reveal_summary, error_text=reveal_errors\)\s*"
        r"for cls in \(([^)]*)\)",
        source,
    )
    assert len(built) == 1, (
        f"expected the detail route to build its reveal sets once, through revealable() behind "
        f"both acts; found {built}. A masked property the reveal never names is invisible to an "
        f"operator who deliberately asked for the record."
    )
    assert sorted(m.strip() for m in built[0].split(",")) == [
        "EventInfo",
        "MessageDetail",
        "OutboxInfo",
    ]
    # BACKLOG #2443 added ONE other site, deliberately: the event and alert lists' per-item reveal,
    # which lifts the error-text set on the one row the request names and on no other. It is pinned
    # by its exact spelling so a second such site, or one that reveals more, still fails here.
    per_item = re.findall(
        r"revealed=revealable\(type\(i\), summary=False, error_text=i\.id == reveal\)", source
    )
    assert len(per_item) == 1, f"expected the one per-item reason reveal site, found {per_item}"
    # BACKLOG #2443 step 4 added the connections dashboard's per-connection reveal, pinned the same
    # way: it lifts ConnectionRow's error-text set on the rows of the one name the request gives.
    per_conn = re.findall(
        r"return revealable\(ConnectionRow, summary=False, error_text=_row_conn\(row\) == reveal\)",
        source,
    )
    assert len(per_conn) == 1, f"expected the one per-connection reveal set, found {per_conn}"
    assert source.count("revealed=lifted(r)") == 1, "the per-connection set has one call site"
    # Every other reveal site reads one of those sets, and together they cover all three models.
    sites = [
        s
        for s in re.findall(r"revealed=([^\n,]+?)(?=[,)\n])", source)
        if not s.startswith(("revealable(type(i", "lifted("))
    ]
    models = [m.group(1) for m in (re.fullmatch(r"reveal\[(\w+)\]", s) for s in sites) if m]
    assert len(models) == len(sites), (
        f"a reveal call site in api/app.py does not read the route's revealable() sets: {sites}"
    )
    assert sorted(models) == ["EventInfo", "MessageDetail", "OutboxInfo"], (
        f"expected the detail route's three reveal sites, found {models}. Another one is not "
        f"automatically wrong, but widen this guard deliberately rather than letting it go unchecked."
    )


def test_revealable_lifts_every_masked_property_of_each_model_and_only_on_its_act() -> None:
    """``revealable`` is what the route passes, so it must cover each table on its own act.

    The summary act lifts the summary grammar's set and never the error text; the error act lifts
    this model's error text and never the summary. Asked for neither, nothing is lifted.
    """
    for model_cls, gated in PHI_FIELDS.items():
        summary = MASKED_UNTIL_REVEALED & gated.keys()
        error_text = ERROR_TEXT_MASKED_UNTIL_REVEALED.get(model_cls, frozenset())
        assert error_text <= gated.keys(), model_cls  # the table names only real gated fields
        assert revealable(model_cls, summary=True, error_text=True) == summary | error_text
        assert revealable(model_cls, summary=True, error_text=False) == summary
        assert revealable(model_cls, summary=False, error_text=True) == error_text
        assert revealable(model_cls, summary=False, error_text=False) == frozenset()
    # And a nested row gets no name it does not have: OutboxInfo has no summary.
    assert revealable(OutboxInfo, summary=True, error_text=True) == {"last_error"}


def test_error_text_masking_is_keyed_by_model_and_catches_no_other_surface() -> None:
    """BACKLOG #2436. By property name, ``detail`` would also reach ``CapturedResponseInfo.detail``
    on ``/responses``, a different datum with no reveal act. So the table is keyed by model, and
    that one stays complete for a holder. The list rows' ``error`` is the same stored value the
    open masks, so it is in the table on purpose; the dead-letter row is the control. The event
    and alert reasons joined under BACKLOG #2443."""
    assert dict(ERROR_TEXT_MASKED_UNTIL_REVEALED) == {
        MessageSummary: frozenset({"error"}),
        MessageDetail: frozenset({"error"}),
        OutboxInfo: frozenset({"last_error"}),
        EventInfo: frozenset({"detail"}),
        DeadLetterRow: frozenset({"last_error"}),
        ConnectionEventInfo: frozenset({"reason"}),
        AlertInstanceInfo: frozenset({"reason"}),
        ConnectionRow: frozenset({"error"}),
    }
    holder = _identity(Permission.MESSAGES_VIEW_SUMMARY)
    assert redact_unauthorized(_summary(), holder).error == "****"
    response = CapturedResponseInfo(
        destination_name="OB",
        response_seq=1,
        outcome="nak",
        detail="AE from partner",
        captured_at=0.0,
        body=None,
    )
    assert redact_unauthorized(response, holder).detail == "AE from partner"
    assert redact_unauthorized(_dead(), holder).last_error == "****"  # the control


def test_error_text_is_masked_whole_not_through_the_summary_grammar() -> None:
    """Free error text is not a composed summary. Through ``mask_for_display`` a value with a comma
    would come back as initials, and one shaped like ``MRN 100001`` would keep its tail. Masked
    whole, neither leaks a character nor the value's length."""
    holder = _identity(Permission.MESSAGES_VIEW_SUMMARY)
    for text in ("DOE, JANE rejected", "MRN 100001", "x" * 200):
        assert redact_unauthorized(_dead(last_error=text), holder).last_error == "****"
