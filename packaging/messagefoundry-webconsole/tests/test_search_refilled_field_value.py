# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A needle form refills its Field value box after a run (BACKLOG #6700).

The engine refuses a ``field_value`` beside a content substring, where it used to drop it. Both the
content-search page and the uploaded-log filter refill the box, so an operator who ran a field-path
search and then cleared Field path to search a substring would have posted the leftover value and
been refused. These tests resubmit the page's own refilled form, as a browser would, and pin both
sides: the leftover is not sent, and a value the operator typed still reaches the engine's refusal.
"""

from __future__ import annotations

import itertools
import re
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import httpx
from _webui_support import _add, _client, _cookie_login, _seed, _service
from test_uploaded_logs_ui import _app, _login, _upload
from test_uploaded_logs_ui import _service as _uploads_service

from messagefoundry.auth import Role
from messagefoundry.pipeline import Engine
from messagefoundry.store.content_search import sends_a_needle as engine_sends_a_needle
from messagefoundry_webconsole.routes._common import (
    DROPPED_CONTENT,
    DROPPED_FIELD_VALUE,
)
from messagefoundry_webconsole.routes._common import sends_a_needle as console_sends_a_needle

_REFUSAL = "field_value applies only to an HL7 field path, not to content"
#: The result note for no match, anchored so "10 match(es)" does not satisfy it.
_NO_MATCH = re.compile(r">0 match\(es\) after")


class _FormInputs(HTMLParser):
    """The ``name``/``value`` of every ``<input>`` inside the form posting to ``action``: what a
    browser would submit if the operator changed nothing."""

    def __init__(self, action: str) -> None:
        super().__init__()
        self._action = action
        self._inside = False
        self.values: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = dict(attrs)
        if tag == "form":
            self._inside = a.get("action") == self._action
        elif tag == "input" and self._inside and a.get("name"):
            self.values[str(a["name"])] = a.get("value") or ""

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._inside = False


def _refilled(page: str, action: str) -> dict[str, str]:
    parser = _FormInputs(action)
    parser.feed(page)
    assert parser.values, f"no form posting to {action} on the page"
    return parser.values


async def test_a_substring_search_from_a_refilled_page_succeeds(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine)  # PID-3 = 100, body carries DOE^JANE
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        first = await c.post(
            "/ui/messages/search/run",
            data={"field_path": "PID-3", "field_value": "100", "target": "both"},
        )
        assert first.status_code == 200, first.text
        form = _refilled(first.text, "/ui/messages/search/run")
        assert form["field_value"] == "100"  # control: the page did refill the box

        # The operator clears Field path and types a substring, leaving the refilled value alone.
        form.update(field_path="", content="DOE^JANE", target="both")
        second = await c.post("/ui/messages/search/run", data=form)
        assert second.status_code == 200, second.text
        assert _REFUSAL not in second.text
        assert "match(es)" in second.text and f"/ui/messages/{mid}" in second.text
        # The leftover was not run as a criterion, so the page no longer refills it.
        assert _refilled(second.text, "/ui/messages/search/run")["field_value"] == ""


async def test_a_typed_field_value_beside_a_substring_is_refused_not_dropped(
    engine: Engine,
) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await _seed(engine)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        # Typed on a bare form: no refilled value to match.
        r = await c.post(
            "/ui/messages/search/run", data={"field_value": "100", "content": "DOE^JANE"}
        )
        assert r.status_code == 400, r.text
        assert _REFUSAL in r.text
        # Resubmitted unchanged from the refusal page, which echoes the typed value back: still
        # the operator's value, so it is refused again rather than dropped.
        again = await c.post(
            "/ui/messages/search/run", data=_refilled(r.text, "/ui/messages/search/run")
        )
        assert again.status_code == 400, again.text
        assert _REFUSAL in again.text
        # A Field path of only spaces is no path, so its refusal page carries no marker either.
        r = await c.post("/ui/messages/search/run", data={"field_path": "  ", "field_value": "100"})
        assert r.status_code == 400, r.text
        form = _refilled(r.text, "/ui/messages/search/run")
        form.update(content="DOE^JANE")
        r = await c.post("/ui/messages/search/run", data=form)
        assert r.status_code == 400, r.text
        assert _REFUSAL in r.text

        # Changed on a refilled page: the posted value differs from the one the page refilled.
        first = await c.post(
            "/ui/messages/search/run", data={"field_path": "PID-3", "field_value": "100"}
        )
        form = _refilled(first.text, "/ui/messages/search/run")
        form.update(field_path="", content="DOE^JANE", field_value="200")
        r = await c.post("/ui/messages/search/run", data=form)
        assert r.status_code == 400, r.text
        assert _REFUSAL in r.text


async def test_a_refilled_field_value_with_its_field_path_still_searches(engine: Engine) -> None:
    """Control for the rule's scope: resubmitting the refilled field-path search unchanged still
    sends the Field value, so it filters on it rather than running a presence test."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await _seed(engine)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        first = await c.post(
            "/ui/messages/search/run", data={"field_path": "PID-3", "field_value": "999"}
        )
        assert _NO_MATCH.search(first.text)  # control: 999 matches nothing
        again = await c.post(
            "/ui/messages/search/run", data=_refilled(first.text, "/ui/messages/search/run")
        )
        assert again.status_code == 200, again.text
        assert _NO_MATCH.search(again.text), "the refilled Field value was dropped"


async def test_an_uploaded_log_substring_filter_from_a_refilled_page_succeeds(
    engine: Engine, tmp_path: Path
) -> None:
    service = await _uploads_service(engine, ("op", Role.OPERATOR))
    transport = httpx.ASGITransport(app=_app(engine, service, tmp_path))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await _login(c, "op")
        fid = await _upload(c)
        action = f"/ui/uploaded-logs/file/{fid}/filter"
        first = await c.post(action, data={"field_path": "PID-3", "field_value": "MRN999"})
        assert first.status_code == 200, first.text
        assert "ADT^A04" in first.text and "ADT^A01" not in first.text  # control: it filtered
        form = _refilled(first.text, action)
        assert form["field_value"] == "MRN999"

        form.update(field_path="", content="MRN123")
        second = await c.post(action, data=form)
        assert second.status_code == 200, second.text
        assert "ADT^A01" in second.text and "ADT^A04" not in second.text

        form.update(field_value="MRN000")  # typed, so it is sent and refused
        third = await c.post(action, data=form)
        assert third.status_code == 400, third.text
        assert _REFUSAL in third.text

        # Another criterion refused first: the page shows the value the run would have used, so
        # the dropped leftover does not come back without its marker.
        form = _refilled(first.text, action)
        form.update(field_path="", content="MRN123", control_id="C" * 300)
        fourth = await c.post(action, data=form)
        assert fourth.status_code == 400, fourth.text
        assert _refilled(fourth.text, action)["field_value"] == ""


# --- BACKLOG #6700 items 2, 7, 8, 9 and 24 ----------------------------------------------------------

_BOTH = "provide exactly one of a content substring or an HL7 field path"


async def test_a_refilled_substring_beside_a_typed_field_path_is_dropped_with_a_notice(
    engine: Engine,
) -> None:
    """Item 7: an operator who ran a substring search and then types a Field path posted the old
    Substring beside it and was refused. Item 8: the page now says the leftover was not sent."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine)  # PID-3 = 100, body carries DOE^JANE
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        first = await c.post("/ui/messages/search/run", data={"content": "DOE^JANE"})
        assert first.status_code == 200, first.text
        assert DROPPED_CONTENT not in first.text  # control: nothing was dropped on the first run
        form = _refilled(first.text, "/ui/messages/search/run")
        assert form["content"] == "DOE^JANE"  # control: the page did refill the box

        form.update(field_path="PID-3", field_value="100")
        second = await c.post("/ui/messages/search/run", data=form)
        assert second.status_code == 200, second.text
        assert _BOTH not in second.text
        assert f"/ui/messages/{mid}" in second.text
        assert DROPPED_CONTENT in second.text
        assert _refilled(second.text, "/ui/messages/search/run")["content"] == ""

        # Changed on the refilled page: the operator's own value, so it is sent and refused.
        form = _refilled(first.text, "/ui/messages/search/run")
        form.update(field_path="PID-3", content="SMITH")
        third = await c.post("/ui/messages/search/run", data=form)
        assert third.status_code == 400, third.text
        assert _BOTH in third.text and DROPPED_CONTENT not in third.text


async def test_a_dropped_field_value_leftover_is_named_on_the_page(engine: Engine) -> None:
    """Item 8, the Field value side."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await _seed(engine)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        first = await c.post(
            "/ui/messages/search/run", data={"field_path": "PID-3", "field_value": "100"}
        )
        assert DROPPED_FIELD_VALUE not in first.text
        form = _refilled(first.text, "/ui/messages/search/run")
        form.update(field_path="", content="DOE^JANE")
        second = await c.post("/ui/messages/search/run", data=form)
        assert second.status_code == 200, second.text
        assert DROPPED_FIELD_VALUE in second.text


async def test_resubmitting_a_refusal_page_that_carried_a_path(engine: Engine) -> None:
    """Item 24: a refusal page rendered with a Field path holds the Field value marker and no
    Substring marker. Resubmitted unchanged, both terms are the operator's and are refused again;
    with Field path cleared the Field value is the leftover; with Substring cleared the field
    search runs on the value."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine)
    action = "/ui/messages/search/run"
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        refused = await c.post(
            action, data={"field_path": "PID-3", "field_value": "999", "content": "DOE^JANE"}
        )
        assert refused.status_code == 400, refused.text
        form = _refilled(refused.text, action)
        assert form["field_value_refilled"] == "999" and form["content_refilled"] == ""

        again = await c.post(action, data=form)
        assert again.status_code == 400, again.text
        assert _BOTH in again.text

        form = _refilled(refused.text, action)
        form.update(field_path="")
        sub = await c.post(action, data=form)
        assert sub.status_code == 200, sub.text
        assert f"/ui/messages/{mid}" in sub.text and DROPPED_FIELD_VALUE in sub.text

        form = _refilled(refused.text, action)
        form.update(content="")
        field = await c.post(action, data=form)
        assert field.status_code == 200, field.text
        assert _NO_MATCH.search(field.text), "the refilled Field value was not applied"


async def test_a_field_value_of_only_spaces_alone_is_no_criterion(engine: Engine) -> None:
    """Item 2: the console counted a Field value of only spaces as a criterion, where the engine's
    rule for an optional needle does not, so it searched and was refused. It is the bare form now."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await _seed(engine)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.post("/ui/messages/search/run", data={"field_value": "   "})
        assert r.status_code == 200, r.text
        assert "match(es)" not in r.text and _BOTH not in r.text


def test_console_needle_rule_matches_the_engine() -> None:
    """The console's copy of the optional-needle rule agrees with the engine's on every case."""
    texts = [None, "", " ", "　", "DOE", " DOE "]
    # A stored preset can hand the rule a non-text Field value; the engine ignores one.
    values: list[Any] = [*texts, 5, 0]
    for content, path, value in itertools.product(texts, texts, values):
        assert console_sends_a_needle(content, path, value) == engine_sends_a_needle(
            content, path, value
        ), (content, path, value)


async def test_an_uploaded_log_refusal_echoes_no_control_character_and_applies_no_refused_filter(
    engine: Engine, tmp_path: Path
) -> None:
    """Item 9: the refusal arm echoed control_id raw, control characters included, and still
    applied it, so the listing was filtered by the refused value. Control: a valid message_type
    beside a refused criterion is still applied."""
    service = await _uploads_service(engine, ("op", Role.OPERATOR))
    transport = httpx.ASGITransport(app=_app(engine, service, tmp_path))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await _login(c, "op")
        fid = await _upload(c)
        action = f"/ui/uploaded-logs/file/{fid}/filter"
        r = await c.post(action, data={"control_id": "MSG1\x01", "message_type": "ADT\x02"})
        assert r.status_code == 400, r.text
        assert "\x01" not in r.text and "\x02" not in r.text
        assert "2 of 2 message(s)" in r.text, "a refused filter was applied"
        assert 'value="MSG1"' in r.text  # the echo, with the control character dropped

        r = await c.post(action, data={"content": "M" * 600, "message_type": "ADT^A04"})
        assert r.status_code == 400, r.text
        assert "1 of 2 message(s)" in r.text, "a valid filter beside a refused one was dropped"


async def test_a_refilled_substring_beside_a_path_with_no_value_is_still_refused(
    engine: Engine,
) -> None:
    """Review round 1: dropping the Substring beside a Field path alone would run a presence test
    the operator may not have meant, which decrypts bodies, where origin/main refused the pair."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await _seed(engine)
    action = "/ui/messages/search/run"
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        first = await c.post(action, data={"content": "DOE^JANE"})
        form = _refilled(first.text, action)
        form.update(field_path="PID-3")
        r = await c.post(action, data=form)
        assert r.status_code == 400, r.text
        assert _BOTH in r.text and DROPPED_CONTENT not in r.text


async def test_a_refusal_after_a_dropped_substring_puts_it_back_with_its_marker(
    engine: Engine,
) -> None:
    """Review round 1: a typo in the new Field path made the refusal page come back with the
    Substring box empty. It is put back with its marker, so the corrected resubmit drops it again."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine)
    action = "/ui/messages/search/run"
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        first = await c.post(action, data={"content": "DOE^JANE"})
        form = _refilled(first.text, action)
        form.update(field_path="P", field_value="100")
        typo = await c.post(action, data=form)
        assert typo.status_code == 400, typo.text
        again = _refilled(typo.text, action)
        assert again["content"] == "DOE^JANE" and again["content_refilled"] == "DOE^JANE"
        again.update(field_path="PID-3")
        fixed = await c.post(action, data=again)
        assert fixed.status_code == 200, fixed.text
        assert f"/ui/messages/{mid}" in fixed.text and DROPPED_CONTENT in fixed.text


async def test_an_uploaded_log_refusal_puts_a_dropped_substring_back(
    engine: Engine, tmp_path: Path
) -> None:
    """The same on the uploaded-log filter's model-refusal arm."""
    service = await _uploads_service(engine, ("op", Role.OPERATOR))
    transport = httpx.ASGITransport(app=_app(engine, service, tmp_path))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await _login(c, "op")
        fid = await _upload(c)
        action = f"/ui/uploaded-logs/file/{fid}/filter"
        first = await c.post(action, data={"content": "MRN123"})
        form = _refilled(first.text, action)
        form.update(field_path="PID-3", field_value="MRN999", control_id="C" * 300)
        r = await c.post(action, data=form)
        assert r.status_code == 400, r.text
        back = _refilled(r.text, action)
        assert back["content"] == "MRN123" and back["content_refilled"] == "MRN123"
