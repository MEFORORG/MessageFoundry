# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Worked example (WP-7b): Handler-level cross-field consistency on an ADT feed.

Strict validation (`validation.strict`) checks a message against the HL7 *schema* — segment
cardinality, datatypes, table values. It does **not** check business *coherence across fields*: that
required identifiers are present, that the trigger event is echoed consistently, or that admit ≤
discharge. ASVS 2.2.3 / 2.1.2 place that on the application — i.e. the Router/Handler.

This sample composes the generic primitives in
[messagefoundry.parsing.consistency](../../messagefoundry/parsing/consistency.py) into ADT-specific
rules, and shows the two ways a Handler can act on a failure:

  - a message a downstream system can't safely consume (missing id, malformed date) → **dead-letter**
    by raising ``ConsistencyError`` (logged ``ERROR`` + AlertSink; the error text is PHI-safe);
  - a coherence issue you'd rather quietly drop → **filter** by ``return None`` (logged ``FILTERED``).

The library only *detects*; the Handler *decides* — keeping the Handler a pure function of the
message (required by the at-least-once re-run invariant; see CLAUDE.md §2).

Run::

    python -m messagefoundry serve --config samples/consistency --db ./mf.db --env dev
"""

from messagefoundry import File, MLLP, Send, handler, inbound, outbound, router
from messagefoundry.parsing.consistency import (
    ConsistencyError,
    check,
    dates_in_order,
    required,
    same_across,
    valid_date,
)

inbound("IB_ACME_ADT", MLLP(port=2576), router="adt_router")
outbound("FILE-OUT_ACME_ADT", File(directory="./out/adt-validated", filename="{MSH-10}.hl7"))


@router("adt_router")
def route(msg):  # type: ignore[no-untyped-def]
    return ["validate_and_archive"] if msg.message_code == "ADT" else []


@handler("validate_and_archive")
def validate_and_archive(msg):  # type: ignore[no-untyped-def]
    # Compose the generic primitives into ADT business rules. Each returns PHI-safe Violations
    # (field path + rule, never the value); check() flattens them for a single decision.
    violations = check(
        required(msg, "PID-3", "PID-5", "MSH-10"),  # patient id, name, message control id present
        same_across(
            msg, "MSH-9.2", "EVN-1"
        ),  # trigger event echoed in EVN-1 (both required in ADT)
        valid_date(msg, "PID-7"),  # date of birth well-formed when present
        dates_in_order(msg, "PV1-44", "PV1-45"),  # admit (44) must not be after discharge (45)
    )
    if violations:
        # Inconsistent → error/dead-letter so an operator sees it. The ConsistencyError string is
        # built from rule + paths only, so it is safe to log and store (no PHI). To instead drop it
        # silently (FILTERED), `return None` here.
        raise ConsistencyError(violations)
    return Send("FILE-OUT_ACME_ADT", msg)
