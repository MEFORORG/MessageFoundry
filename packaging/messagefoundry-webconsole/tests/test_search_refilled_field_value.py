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

from html.parser import HTMLParser
from pathlib import Path

import httpx
from _webui_support import _add, _client, _cookie_login, _seed, _service
from test_uploaded_logs_ui import _app, _login, _upload
from test_uploaded_logs_ui import _service as _uploads_service

from messagefoundry.auth import Role
from messagefoundry.pipeline import Engine

_REFUSAL = "field_value applies only to an HL7 field path, not to content"


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
        assert "0 match(es)" in first.text  # control: 999 matches nothing
        again = await c.post(
            "/ui/messages/search/run", data=_refilled(first.text, "/ui/messages/search/run")
        )
        assert again.status_code == 200, again.text
        assert "0 match(es)" in again.text, "the refilled Field value was dropped"


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
