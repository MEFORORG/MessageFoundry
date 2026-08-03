# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The synchronous-reply injection seam (ADR 0154 D2) — the types, and the PHI property they carry.

``InboundReply.body`` is the partner's reply: PHI, decrypted out of the store. The design rule is
structural — reply-derived bytes never reach an exception, a log call, a ``connection_event.reason``
or a ``message_events.detail`` — and the redacting ``__repr__`` is what makes the *accidental* case
safe too. A frozen dataclass's default repr would put the body into any log line, traceback or
assertion message that interpolates the object, which is the kind of leak that survives review
because nothing looks wrong at the call site.
"""

from __future__ import annotations

from messagefoundry.transports.base import (
    InboundReply,
    ReplyOutcome,
    SourceConnector,
)

# A JSON reply carrying an identifier. Chosen deliberately: safe_text is an HL7-shaped redactor, so
# it would NOT scrub this — which is exactly why the rule here is structural rather than a scrub.
PHI_BODY = '{"patient":{"mrn":"100","name":"DOE^JANE"},"status":"accepted"}'


def test_repr_never_contains_the_body() -> None:
    reply = InboundReply(
        outcome=ReplyOutcome.REPLY,
        body=PHI_BODY,
        content_type="application/json",
        destination="OB_PARTNER",
        response_seq=1,
        waited_ms=42,
    )
    text = repr(reply)
    for leak in ("100", "DOE", "JANE", "mrn", PHI_BODY):
        assert leak not in text, f"{leak!r} reached repr(InboundReply) — this is the PHI leak"

    # ... while everything an operator actually needs is still there.
    assert "reply" in text and "OB_PARTNER" in text and "42" in text
    assert "redacted" in text


def test_repr_survives_an_absent_body() -> None:
    # The refusal outcomes carry no body; repr must not blow up mid-log.
    assert "0 chars redacted" in repr(InboundReply(outcome=ReplyOutcome.TIMEOUT))


def test_an_f_string_of_the_object_is_safe() -> None:
    # The realistic accident: logger.warning("sync reply: %s", reply) or an f-string in an assert.
    reply = InboundReply(outcome=ReplyOutcome.REJECTED, body=PHI_BODY, destination="OB_PARTNER")
    assert "DOE" not in f"{reply}"
    assert "DOE" not in str(reply)
    assert "DOE" not in "{}".format(reply)  # noqa: UP032 - the point is the format path


def test_degraded_is_a_distinct_outcome_from_timeout() -> None:
    # The SLO series rate(timeout)/rate(total) IS the proxy API's error budget, so our own store
    # errors and rendezvous refusals must never be counted as the partner failing to answer.
    assert ReplyOutcome.DEGRADED is not ReplyOutcome.TIMEOUT
    assert ReplyOutcome.DEGRADED.value == "degraded"
    # Every D5 outcome-table row has exactly one member.
    assert {o.value for o in ReplyOutcome} == {
        "reply",
        "empty",
        "rejected",
        "failed",
        "purged",
        "no_route",
        "timeout",
        "degraded",
        "shutting_down",
    }


def test_the_seam_defaults_to_absent_so_the_202_path_is_unchanged() -> None:
    # AC-8: an inbound without reply_from must be byte-identical. The default is what guarantees it.
    assert SourceConnector.sync_reply is None


def test_the_resolver_takes_only_a_committed_message_id() -> None:
    # ACK-on-receipt, enforced structurally rather than by convention: the id does not exist until
    # the body is durably committed to the ingress stage, so there is no shape of this call that
    # observes an uncommitted message.
    import inspect

    from messagefoundry.transports.base import SyncReplyResolver

    args = SyncReplyResolver.__args__  # Callable[[str], Awaitable[InboundReply]]
    assert args[0] is str, f"the resolver takes {args[0]!r}, not a message_id"
    assert len(args) == 2, "the resolver must take exactly one argument — the committed message_id"
    assert inspect.isclass(str)
