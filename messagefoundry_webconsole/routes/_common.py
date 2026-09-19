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
from typing import Final
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


# --- The rules the console's own filter forms enforce (BACKLOG #1740) -----------------------------
#
# The console mounts inside the engine and calls the JSON handlers BY REFERENCE, so a handler's own
# ``Query(...)`` declaration never runs for a /ui caller. Every rule ``api/validation.py`` defines
# was therefore absent on this surface: ``/messages`` declares ``channel_id: ConnectionName`` while
# ``/ui/messages`` declared a plain ``str`` with a length bound, so a value the JSON route refuses
# reached the store query through the console.
#
# Each rule below reuses the twin's ANNOTATED TYPE rather than restating its pattern. That is what
# stops the two surfaces drifting: narrowing ``ConnectionName`` narrows both at once.

#: Each filter rule: the annotated type the JSON twin declares for the same data item, and the
#: sentence the console shows when it refuses a value.
#:
#: ``status`` and ``event kind`` resolve to the same annotated type today. They are two entries
#: anyway, because the twin declares them as two named rules and narrowing one later must not
#: silently narrow the other.
#:
#: The sentence describes the ALPHABET and never quotes the value. Pydantic's own message quotes the
#: offending input, and these are PHI-shaped pages; the value goes back only into the escaped form
#: field the operator typed it into, so they can correct it.
_FILTER_RULES: Final[dict[str, tuple[TypeAdapter[str], str]]] = {
    "connection": (
        TypeAdapter(ConnectionName),
        "a connection name is a letter, then letters, digits, underscore or hyphen",
    ),
    "status": (
        TypeAdapter(StatusFilter),
        "a status is one word of letters and underscores",
    ),
    "event kind": (
        TypeAdapter(EventKindFilter),
        "an event kind is one word of letters and underscores",
    ),
    "message type": (
        TypeAdapter(MessageTypeFilter),
        "a message type is printable text with no control characters",
    ),
    "control id": (
        TypeAdapter(ControlIdFilter),
        "a control id is printable text with no control characters",
    ),
}

#: Which /ui routes check which filters in their own handler body, and against which rule above.
#:
#: Here rather than beside each route because it is the console's answer to a question asked ACROSS
#: routes -- "which operator-typed filter carries which rule" -- and because the golden input-rule
#: table reads this same mapping. A table built from a second, test-side transcription would agree
#: with a route that had stopped applying a rule.
#:
#: These routes are body-checked rather than annotated because each has a filter FORM. An annotation
#: makes FastAPI answer a bare 422 and discard the submission; these answer 400 and re-render the
#: form carrying what the operator typed. The /ui routes whose values the console itself mints --
#: ``/ui/dead-letters``, the per-name controls, the purge pages -- are annotated instead, and so are
#: absent here.
UI_BODY_FILTER_RULES: Final[dict[str, dict[str, str]]] = {
    # Keyed as ``pages.messages`` / ``pages.message_search`` / ``pages.events`` key their echo
    # keywords, so the dict a route checks IS the dict it renders back.
    "/ui/messages": {
        "channel_id": "connection",
        "status": "status",
        "message_type": "message type",
        "control_id": "control id",
    },
    # The same four items ``GET /messages/search`` declares, and the same four
    # ``SearchPresetCriteria`` already enforces on the console's POST search arm.
    #
    # ``field_path`` is deliberately absent: its grammar lives in ``parsing.peek.parse_path``, which
    # ``store.content_search.make_spec`` already applies, and ``api/validation.py`` declares no
    # second copy of it. ``target`` is a closed literal the route signature already pins.
    "/ui/messages/search": {
        "channel_id": "connection",
        "status": "status",
        "message_type": "message type",
        "control_id": "control id",
    },
    "/ui/events": {"connection": "connection", "kind": "event kind"},
}


class FilterRefused(Exception):
    """A /ui filter value the JSON twin would refuse, carrying the operator-facing sentence.

    Deliberately NOT a ``ValueError``. ``ui_messages`` already catches ``ValueError`` for a
    different refusal with a different message (a malformed received-date bound, BACKLOG #1744), and
    a subclass would put the ORDER of two ``except`` clauses in charge of which sentence an operator
    reads -- a thing no test would fail on and no reviewer would see.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def check_filters(rules: Mapping[str, str], values: Mapping[str, object]) -> None:
    """Raise :class:`FilterRefused` for the first value in ``values`` its rule would refuse.

    ``rules`` is one route's row out of :data:`UI_BODY_FILTER_RULES`, mapping a form field name to a
    key of :data:`_FILTER_RULES`; ``values`` is that route's already-built echo dict, so the operator
    keeps what they typed on the refusal render. A blank or absent value is "no filter" and passes,
    which is what the twin's ``Query(None)`` default means too.

    ``values`` is typed ``Mapping[str, object]`` because every caller passes a ``TypedDict``, which
    mypy will not narrow to ``Mapping[str, str]``. Nothing is skipped for being the wrong type: a
    non-string value is handed to the rule and refused by it, the same as a bad string.

    First refusal rather than a collected list: the pages carry a single banner, and a form with two
    bad fields costs one round trip to correct either way.
    """
    for field, rule in rules.items():
        value = values.get(field, "")
        if not value:
            continue
        adapter, sentence = _FILTER_RULES[rule]
        try:
            adapter.validate_python(value)
        except ValidationError as exc:
            raise FilterRefused(sentence) from exc


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
