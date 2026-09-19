# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1743: the messages and dead-letter listings page, and their links keep the filters.

Both routes already accepted ``limit``/``offset`` and both response models already carried
``total``/``limit``/``offset``. What was missing was the console end: the pages rendered a bare
``N of TOTAL (offset 0)`` line with no way forward, so an operator reached only the first window of
any result set and a count they could read as the whole of it.

The defect these tests are really aimed at is the SECOND one, which a pager introduces rather than
fixes: a Previous/Next link that drops the active filters re-runs a wider query and still returns
rows, so the operator reads a result set under a filter they typed and the engine did not apply.
Each test below therefore seeds rows that the filter EXCLUDES and asserts they stay off both pages
-- a pager that lost its filters would surface them, and a bare "the link exists" assertion would
not notice.
"""

from __future__ import annotations

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine

PW = "a-strong-test-passphrase"
ADT = "MSH|^~\\&|S|F|R|RF|20260604||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"
ORU = "MSH|^~\\&|S|F|R|RF|20260604||ORU^R01|MSG9|P|2.5.1\rPID|1||101^^^H^MR||ROE^JOHN\r"


async def _service(engine: Engine) -> AuthService:
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    user_id = await service.create_local_user(
        username="op",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.ADMINISTRATOR.value],
        actor="test",
    )
    await service.set_channel_scope(user_id, [ALL_CHANNELS], actor="test")
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id, password_hash=user.password_hash, must_change_password=False
    )
    return service


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(engine, auth=service, serve_ui=True))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def _login(client: httpx.AsyncClient) -> None:
    r = await client.post("/ui/login", data={"username": "op", "password": PW})
    assert r.status_code in (200, 303), r.text


def _next_href(html: str) -> str:
    """The Next link's href, read out of the rendered page rather than rebuilt from the inputs.

    Rebuilding it here would make the assertion a restatement of the test's own arithmetic; taking
    it from the markup is what makes the round-trip check a measurement of the page.
    """
    marker = '<a href="'
    for chunk in html.split(marker)[1:]:
        href, _, rest = chunk.partition('"')
        if ">Next<" in rest:
            return href
    raise AssertionError("no Next link in the page")


#: Named rather than pasted, so this source file stays pure ASCII: a literal arrow here would be the
#: thing under test, and it would also raise UnicodeEncodeError on a stock cp1252 console.
_ARROWS = ("\N{LEFTWARDS ARROW}", "\N{RIGHTWARDS ARROW}")


@pytest.mark.parametrize("glyph", _ARROWS)
def test_no_arrow_glyph_reaches_the_pager(glyph: str) -> None:
    """CLAUDE.md section 11: the words, never the arrows.

    Pinned because the one pager that existed before this shared builder embedded both, and a
    shared builder hands whatever it was given to every caller at once. ``offset=3`` of ``total=9``
    is the window where BOTH links render, so neither branch escapes the scan -- a render at an
    edge would leave one of them unmeasured and still pass.
    """
    from messagefoundry_webconsole.pages import _common

    rendered = str(_common._pager(path="/ui/x", total=9, limit=3, offset=3, shown=3, noun="thing"))
    assert glyph not in rendered
    assert ">Previous<" in rendered and ">Next<" in rendered


def test_the_pager_omits_an_empty_filter_rather_than_sending_it_blank() -> None:
    """An empty string is a VALUE at the route, not the absence of one: ``?channel_id=`` arrives as
    ``""`` and would reach the store as a filter nobody asked for. The blank ones must not be sent.

    NEGATIVE CONTROL in the same assertion: the non-empty neighbour IS sent, so a builder that
    dropped every filter would fail this rather than pass it.
    """
    from messagefoundry_webconsole.pages import _common

    rendered = str(
        _common._pager(
            path="/ui/messages",
            total=9,
            limit=3,
            offset=0,
            shown=3,
            noun="message(s)",
            filters={"channel_id": "ch1", "status": "", "message_type": "ADT^A01"},
        )
    )
    assert "channel_id=ch1" in rendered
    assert "message_type=ADT%5EA01" in rendered  # the caret rides as an encoded query value
    assert "status=" not in rendered


def test_a_window_past_the_end_says_so_and_steps_back_to_real_rows() -> None:
    """A bookmarked page-N link outlives the rows it named: retention purges, a filter narrows, or
    an offset is typed by hand. The window is then empty and the old arithmetic printed a range
    that contradicted the empty table under it, with a Previous that landed past the end again.

    Both halves are asserted, because fixing only the sentence leaves the operator one click from a
    second empty page, and fixing only the link leaves a count that reads as rows they cannot see.
    """
    from messagefoundry_webconsole.pages import _common

    rendered = str(
        _common._pager(path="/ui/messages", total=3, limit=50, offset=100, shown=0, noun="msg(s)")
    )
    assert "0 of 3 msg(s)" in rendered
    assert "0-100" not in rendered, "the counter claimed a window that holds no rows"
    assert "offset=0" in rendered, (
        "Previous must reach the last page with rows, not one window back"
    )
    assert ">Next<" not in rendered

    # Past the end of a MULTI-page set: Previous goes to the last populated page, not to zero.
    deep = str(
        _common._pager(path="/ui/messages", total=120, limit=50, offset=500, shown=0, noun="msg(s)")
    )
    assert "0 of 120 msg(s)" in deep and "offset=100" in deep


async def test_the_messages_pager_pages_and_carries_every_filter(engine: Engine) -> None:
    """Three ADT on ch1 plus an ORU the message_type filter excludes, read two at a time.

    The ORU is the load-bearing row: it is the one a Next link that dropped ``message_type`` would
    pull into the second page, and the one that makes ``of 3`` rather than ``of 4`` a real check on
    the count as well as on the link.
    """
    service = await _service(engine)
    for n in range(3):
        await engine.store.enqueue_message(
            channel_id="ch1",
            raw=ADT,
            deliveries=[("archive", ADT)],
            control_id=f"ADT{n}",
            message_type="ADT^A01",
            source_type="file",
        )
    await engine.store.enqueue_message(
        channel_id="ch1",
        raw=ORU,
        deliveries=[("archive", ORU)],
        control_id="ORU0",
        message_type="ORU^R01",
        source_type="file",
    )
    filters = {"channel_id": "ch1", "message_type": "ADT^A01"}
    async with _client(engine, service) as c:
        await _login(c)
        first = await c.get("/ui/messages", params={**filters, "limit": 2, "offset": 0})
        assert first.status_code == 200, first.text
        assert "1-2 of 3 message(s)" in first.text
        assert ">Next<" in first.text and ">Previous<" not in first.text

        href = _next_href(first.text).replace("&amp;", "&")
        assert href == "/ui/messages?channel_id=ch1&message_type=ADT%5EA01&limit=2&offset=2"

        last = await c.get(href)
        assert last.status_code == 200, last.text
        assert "3-3 of 3 message(s)" in last.text
        assert ">Previous<" in last.text and ">Next<" not in last.text

        # The two pages together are the filtered set, and the excluded message is on neither.
        both = first.text + last.text
        assert [n for n in range(3) if f"ADT{n}" in both] == [0, 1, 2]
        assert "ORU0" not in both, "the pager widened the query it was replaying"


async def test_the_dead_letter_pager_pages_and_carries_both_filters(engine: Engine) -> None:
    """Three dead deliveries to one destination plus one to another, read two at a time.

    ``/ui/dead-letters`` draws no filter form, so before this change its two query filters never
    reached the page builder at all. They do now for one reason: the links have to replay them. The
    ``OB_OTHER`` row is what proves they were replayed rather than merely accepted.
    """
    service = await _service(engine)

    async def _dead(destination: str, control_id: str) -> None:
        await engine.store.enqueue_message(
            channel_id="ch1",
            raw=ADT,
            deliveries=[(destination, ADT)],
            control_id=control_id,
            message_type="ADT^A01",
            source_type="file",
            now=0.0,
        )
        for item in await engine.store.claim_ready(now=0.0):
            await engine.store.dead_letter_now(item.id, "permanent reject", now=1.0)

    for n in range(3):
        await _dead("OB_ACME_ADT", f"DL{n}")
    await _dead("OB_OTHER", "OTHER0")

    filters = {"channel_id": "ch1", "destination_name": "OB_ACME_ADT"}
    async with _client(engine, service) as c:
        await _login(c)
        first = await c.get("/ui/dead-letters", params={**filters, "limit": 2, "offset": 0})
        assert first.status_code == 200, first.text
        assert "1-2 of 3 dead delivery(s)" in first.text
        assert ">Next<" in first.text and ">Previous<" not in first.text

        href = _next_href(first.text).replace("&amp;", "&")
        assert href == (
            "/ui/dead-letters?channel_id=ch1&destination_name=OB_ACME_ADT&limit=2&offset=2"
        )

        last = await c.get(href)
        assert last.status_code == 200, last.text
        assert "3-3 of 3 dead delivery(s)" in last.text
        assert ">Previous<" in last.text and ">Next<" not in last.text
        assert "OB_OTHER" not in last.text, "the pager widened the query it was replaying"


async def test_the_capped_pages_say_they_are_windows_rather_than_the_record(engine: Engine) -> None:
    """BACKLOG #1743 item 3: neither capped page may read as the whole log.

    Neither can page -- ``list_audit`` and the security-event listing take a limit and no offset,
    and there is no count to put in a window-of-total line -- so the correction is the claim, not a
    control: a reader who takes either page for the complete record reads an absence on screen as
    an absence in the record. BOTH pages are asserted because they are capped by one constant and
    disclosed by one helper, and covering only the first would leave the second free to drift.

    The bound itself is in the assertion: "capped at the newest 200" is the sentence that separates
    a log holding 200 entries from a log holding 200,000, and a bare count states neither.
    """
    service = await _service(engine)
    async with _client(engine, service) as c:
        await _login(c)
        for path, noun in (("/ui/audit", "entry(s)"), ("/ui/security-events", "event(s)")):
            r = await c.get(path)
            assert r.status_code == 200, r.text
            assert "only the most recent" in r.text, path
            assert f"{noun} shown, capped at the newest 200." in r.text, path
