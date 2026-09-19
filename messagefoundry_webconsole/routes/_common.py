# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Small route helpers shared by the admin/account modules (moved from ``api.auth_routes``).

``_form_pairs`` is the stdlib urlencoded-form parser (no python-multipart dep) shared by every
body-carrying /ui admin/account POST; ``_client`` / ``_rate_limited`` are the account-lifecycle
throttle helpers re-implemented package-side (so the package never imports ``auth_routes``);
``check_filters`` applies ``messagefoundry.api.validation``'s rules to the filter values an operator
types into a /ui form, which a direct handler call would otherwise never validate (BACKLOG #1740).
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Final, NamedTuple
from urllib.parse import parse_qsl

from fastapi import HTTPException, Request, status
from pydantic import TypeAdapter, ValidationError

from messagefoundry.api.validation import (
    ConnectionName,
    ControlIdFilter,
    EventKindFilter,
    MessageTypeFilter,
    StatusFilter,
)

_log = logging.getLogger(__name__)

#: How many active alert instances the /ui alerts page asks for. Shared because TWO modules render
#: that page -- ``routes/monitoring.py`` for the page itself and ``routes/monitoring_writes.py`` when
#: a write is refused (BACKLOG #1744). Two copies would drift, and the refusal would then show the
#: operator a shorter list than the page they came from.
ACTIVE_ALERTS_LIMIT = 200


# --- The rules the console applies to its own input (BACKLOG #1740) -------------------------------
#
# The console mounts inside the engine and calls the JSON handlers BY REFERENCE, so a handler's own
# ``Query(...)`` declaration never runs for a /ui caller. Every rule ``api/validation.py`` defines
# was therefore absent on this surface: ``/messages`` declares ``channel_id: ConnectionName`` while
# ``/ui/messages`` declared a plain ``str`` with a length bound, so a value the JSON route refuses
# reached the store query through the console.
#
# Each rule reuses the twin's ANNOTATED TYPE rather than restating its pattern, so narrowing
# ``ConnectionName``'s PATTERN narrows both surfaces at once. The length bounds the /ui routes keep
# in their ``Query(...)`` declarations are NOT part of that: they stay in front of the rule
# deliberately, because a refused value is echoed back into the form and an unbounded one would make
# the refusal page as large as the request.


class FilterRule(NamedTuple):
    """One input rule: what it is called, what enforces it, and what the console says on a refusal.

    ``refusal`` describes the ALPHABET and never quotes the value. Pydantic's own message quotes the
    offending input, and these are PHI-shaped pages; the value goes back only into the escaped form
    field the operator typed it into, so they can correct it.
    """

    name: str
    adapter: TypeAdapter[str]
    refusal: str


#: ``status`` and ``event kind`` are two rules over one annotated type today. They stay two, because
#: the JSON twin declares them as two named rules and narrowing one later must not silently narrow
#: the other.
CONNECTION_RULE = FilterRule(
    "connection",
    TypeAdapter(ConnectionName),
    "a connection name is a letter, then letters, digits, underscore or hyphen",
)
STATUS_RULE = FilterRule(
    "status", TypeAdapter(StatusFilter), "a status is one word of letters and underscores"
)
EVENT_KIND_RULE = FilterRule(
    "event kind",
    TypeAdapter(EventKindFilter),
    "an event kind is one word of letters and underscores",
)
MESSAGE_TYPE_RULE = FilterRule(
    "message type",
    TypeAdapter(MessageTypeFilter),
    "a message type is printable text with no control characters",
)
CONTROL_ID_RULE = FilterRule(
    "control id",
    TypeAdapter(ControlIdFilter),
    "a control id is printable text with no control characters",
)

#: Every rule the console defines. The golden input-rule table resolves an ANNOTATED parameter's own
#: constraint against these, so a parameter and a body check report in the same vocabulary.
FILTER_RULES: Final[tuple[FilterRule, ...]] = (
    CONNECTION_RULE,
    STATUS_RULE,
    EVENT_KIND_RULE,
    MESSAGE_TYPE_RULE,
    CONTROL_ID_RULE,
)

#: Which /ui routes check which filters in their own handler body, and against which rule.
#:
#: Here rather than beside each route because it answers a question asked ACROSS routes -- which
#: operator-typed filter carries which rule -- and because the golden input-rule table reads this
#: same mapping. A table built from a second, test-side transcription would agree with a route that
#: had stopped applying a rule.
#:
#: These routes are body-checked rather than annotated because each has a filter FORM. An annotation
#: makes FastAPI answer a bare 422 and discard the submission; these answer 400 and re-render the
#: form carrying what the operator typed. The /ui routes whose values the console itself mints --
#: ``/ui/dead-letters``, the per-name controls, the purge pages -- are annotated instead, and so are
#: absent here.
UI_BODY_FILTER_RULES: Final[dict[str, dict[str, FilterRule]]] = {
    # Keyed as ``pages.messages`` / ``pages.message_search`` / ``pages.events`` key their echo
    # keywords, so the dict a route checks IS the dict it renders back.
    "/ui/messages": {
        "channel_id": CONNECTION_RULE,
        "status": STATUS_RULE,
        "message_type": MESSAGE_TYPE_RULE,
        "control_id": CONTROL_ID_RULE,
    },
    # The same four items ``GET /messages/search`` declares, and the same four
    # ``SearchPresetCriteria`` already enforces on the console's POST search arm.
    #
    # ``field_path`` is deliberately absent: its grammar lives in ``parsing.peek.parse_path``, which
    # ``store.content_search.make_spec`` already applies, and ``api/validation.py`` declares no
    # second copy of it. ``target`` is a closed literal the route signature already pins.
    "/ui/messages/search": {
        "channel_id": CONNECTION_RULE,
        "status": STATUS_RULE,
        "message_type": MESSAGE_TYPE_RULE,
        "control_id": CONTROL_ID_RULE,
    },
    "/ui/events": {"connection": CONNECTION_RULE, "kind": EVENT_KIND_RULE},
}


def refuse(rule: FilterRule, value: object) -> str | None:
    """``rule.refusal`` if ``rule`` would refuse ``value``, else ``None``.

    The per-VALUE entry point, used directly by the bulk POST routes: they read names out of the
    request body, so there is no FastAPI parameter to annotate, and they are capture-and-continue
    batches that need a verdict per item rather than a short-circuit.

    ``value`` is ``object`` rather than ``str`` so the field-wise caller below can hand over an echo
    dict's value without a cast. Nothing is skipped for being the wrong type: a non-string is handed
    to the rule and refused by it, the same as a bad string.
    """
    try:
        rule.adapter.validate_python(value)
    except ValidationError:
        return rule.refusal
    return None


def check_filters(rules: Mapping[str, FilterRule], values: Mapping[str, object]) -> str | None:
    """The refusal for the first value in ``values`` its rule would refuse, or ``None`` if all pass.

    ``rules`` is one route's row out of :data:`UI_BODY_FILTER_RULES`; ``values`` is that route's
    already-built echo dict, so the operator keeps what they typed on the refusal render. A blank or
    absent value is "no filter" and passes, which is what the twin's ``Query(None)`` default means.

    First refusal rather than a collected list: the pages carry a single banner, and a form with two
    bad fields costs one round trip to correct either way.
    """
    for field, rule in rules.items():
        value = values.get(field, "")
        if value and (refusal := refuse(rule, value)) is not None:
            return refusal
    return None


async def _form_pairs(request: Request) -> list[tuple[str, str]]:
    # stdlib urlencoded-form parsing (no python-multipart dep), like /ui/login. Pair order is
    # preserved so repeated fields (checkboxes, map rows) can be collected positionally.
    # keep_blank_values=True is LOAD-BEARING for the paired-row AD-map forms: a browser posts
    # blank fields (ad_group=, role=) for empty/half-filled rows, and dropping them (the
    # parse_qsl default) shifts the positional pairing so a role from one row silently binds
    # to a group from another — an RBAC mis-grant. With blanks kept, every row contributes
    # exactly one value per field and the row-wise "if g and r" filters drop incomplete rows
    # as intended. Scalar readers are unaffected (dict(pairs).get(k, "") yields "" either way;
    # checkbox values are never blank).
    return parse_qsl((await request.body()).decode("utf-8", "replace"), keep_blank_values=True)


def _client(request: Request) -> str | None:
    # Already proxy-aware: uvicorn runs with forwarded_allow_ips = settings.api.trusted_proxies
    # (defaults to [] = trust nothing), so behind a declared trusted proxy this resolves to the
    # real client. Matches how ``api.auth_routes._client`` records it on the session.
    return request.client.host if request.client else None


def _rate_limited(request: Request, label: str) -> HTTPException:
    """Log a throttled (HTTP 429) attempt so password-spraying is no longer silent (ASVS 16.3.3),
    then return the exception to raise. We log (the rotating general log) rather than write an
    audit_log row per rejection so a sustained flood can't amplify into unbounded DB growth."""
    _log.warning("rate-limited %s attempt from client=%s", label, _client(request))
    return HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "too many attempts; please retry later")
