# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The /ui resend-to-an-alternate-outbound affordance (ADR 0090 residual (a), BACKLOG #123/#1500).

Two halves. The page builders are driven directly, because the form's SHAPE is the control that makes
ADR 0090's ambiguous-source 409 unreachable from the console. The routes are driven over the cookie
flow, because the permission the console re-asserts, the refusal mapping and the re-auth continuation
are only observable through a mounted app.

NOT the edit-and-resubmit editor (ADR 0090 section 9, BACKLOG #153), which is a different endpoint
with different permissions and ships an EDITED body; and not the uploaded-logs resend (ADR 0134),
which injects into an INBOUND. Both live in test_webui.py / test_uploaded_logs_ui.py.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlsplit

import httpx

from messagefoundry.api import create_app
from messagefoundry.api.models import EventInfo, MessageDetail, OutboxInfo
from messagefoundry.auth import Permission, Role
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.service import AuthService
from messagefoundry.config.models import ConnectorType
from messagefoundry.config.settings import AuthSettings
from messagefoundry.config.wiring import ConnectionSpec, OutboundConnection, Registry
from messagefoundry.pipeline import Engine
from messagefoundry_webconsole._html import text
from messagefoundry_webconsole.pages.messages import (
    RESEND_TAIL_WARNING,
    message_detail,
    message_resend_confirm,
    message_resend_done,
)
from messagefoundry_webconsole.routes.core import (
    _RESEND_NAME_MAX,
    RESEND_BLOCKED_NOTICE,
    RESEND_DENIED_NOTICE,
    RESEND_MALFORMED_NOTICE,
    RESEND_MISSING_NOTICE,
)

PW = "a-strong-test-passphrase"
ADT = "MSH|^~\\&|S|F|R|RF|20260604||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"


def _detail(*destinations: str) -> MessageDetail:
    """A rendered-ready detail carrying one outbound row per name in ``destinations``."""
    return MessageDetail(
        id="m1",
        channel_id="ch1",
        received_at=0.0,
        source_type="file",
        control_id="MSG1",
        message_type="ADT^A01",
        status="PROCESSED",
        error=None,
        raw=ADT,
        outbox=[
            OutboxInfo(
                id=f"o{i}",
                destination_name=name,
                status="done",
                attempts=1,
                next_attempt_at=0.0,
                last_error=None,
            )
            for i, name in enumerate(destinations)
        ],
        events=[EventInfo(ts=0.0, event="delivered", destination=None, detail=None)],
    )


# --- the form's shape is the control -------------------------------------------------------------


def test_one_delivery_needs_no_placeholder() -> None:
    """A single-delivery message needs no choice, so the one option stands alone and the browser's own
    first-option default is the right answer. The engine would resolve an omitted source here too --
    naming it explicitly costs nothing and keeps the POST's meaning independent of how many rows the
    message happens to have when it is submitted."""
    html = str(message_detail(_detail("archive")))
    assert 'action="/ui/messages/m1/resend-confirm"' in html
    assert '<option value="archive">archive</option>' in html
    assert "Choose a delivery" not in html


def test_a_fanned_out_message_must_be_given_a_source() -> None:
    """THE 409 THIS FORM EXISTS TO PREVENT. ``ResendRequest.source`` is optional in the model, and the
    engine resolves it only when the origin has exactly ONE delivery -- a fanned-out message with it
    omitted raises ResendError and the endpoint answers 409 (ADR 0090 section 7).

    A browser selects the first option of a select by default, so a plain list of the two destinations
    would have silently chosen one operator's body for them. The disabled placeholder is what makes
    the choice deliberate, and ``required`` is what makes an unchosen submit fail in the browser
    rather than at the engine."""
    html = str(message_detail(_detail("archive", "OB_PARTNER_ADT")))
    assert '<option value="" disabled selected>Choose a delivery</option>' in html
    assert '<select name="source" required>' in html
    assert '<option value="archive">archive</option>' in html
    assert '<option value="OB_PARTNER_ADT">OB_PARTNER_ADT</option>' in html


def test_duplicate_delivery_rows_collapse_to_one_option() -> None:
    """Two rows for one destination (a retry, a replay) are ONE source, so they must not render as two
    identical options -- which would read as a choice that is not one, and would re-introduce the
    placeholder on a message that in fact has a single source."""
    html = str(message_detail(_detail("archive", "archive")))
    assert html.count('<option value="archive">') == 1
    assert "Choose a delivery" not in html


def test_a_message_with_no_delivery_is_explained_not_offered_a_form() -> None:
    """A message that never produced an outbound row (ERROR/FILTERED/UNROUTED) has no transformed body
    to copy, so every resend of it would 409. Rendering the form anyway would be an affordance that
    can only fail."""
    html = str(message_detail(_detail()))
    assert "Resend to another outbound" in html
    assert "no stored delivery" in html
    assert "/ui/messages/m1/resend-confirm" not in html


def test_the_confirm_page_renders_a_refusal_banner_when_given_one() -> None:
    """A refusal is answered ON THIS PAGE, not by a redirect. The banner text is module-fixed and
    passed in by the route; nothing caller-supplied reaches it."""
    html = str(message_resend_confirm("m1", "OB2", "archive", "k1", error=RESEND_BLOCKED_NOTICE))
    assert "nothing was queued" in html
    assert '<p class="banner">' in html
    # NEGATIVE CONTROL: with no error, the only banner is the tail warning -- so the assertion above
    # is about the argument rather than about something the page always renders.
    clean = str(message_resend_confirm("m1", "OB2", "archive", "k1"))
    assert clean.count('class="banner"') == 1
    assert "nothing was queued" not in clean


# --- the confirm page ------------------------------------------------------------------------------


def test_the_confirm_page_states_the_tail_placement_warning() -> None:
    """ADR 0090 section 3 rules that the console affordance WILL warn, and this is that warning.

    Compared through ``text()`` rather than raw, so the constant's WORDING is free to use any
    character the escaper touches. A bare substring compare quietly made ``'`` unusable in operator
    copy to keep one assertion working, which is the test dictating the product."""
    html = str(message_resend_confirm("m1", "OB_PARTNER_ADT", "archive", "k1"))
    assert str(text(RESEND_TAIL_WARNING)) in html


def test_the_warning_makes_no_claim_the_adr_refuses() -> None:
    """ADR 0090 section 3 is explicit that there is NO sequence-key column and no sub-lane, and that a
    resend is not re-inserted into a historical position. A console that offered to preserve order, or
    that named a sequence key, would be promising something the store cannot do. Pinned as a negative
    so a later wording pass cannot quietly add one."""
    warning = RESEND_TAIL_WARNING.lower()
    for forbidden in ("sequence key", "sequence-key", "original position", "in order", "sub-lane"):
        assert forbidden not in warning


def test_the_confirm_page_post_is_body_less() -> None:
    """The whole selection rides the action URL, which is what lets the POST survive a re-auth redirect
    and what keeps a message body out of any server-side draft (CLAUDE.md section 9).

    The action is pinned WHOLE, ``&amp;`` included: that is the correct HTML-attribute spelling of a
    query separator, and a bare ``&`` there is the kind of thing a later edit introduces silently."""
    html = str(message_resend_confirm("m1", "OB_PARTNER_ADT", "archive", "k1"))
    action = (
        'action="/ui/messages/m1/resend'
        '?to=OB_PARTNER_ADT&amp;source=archive&amp;idempotency_key=k1"'
    )
    assert action in html
    # The page chrome carries a sign-out form of its own, so isolate THIS form by its action.
    form = html.split(action, 1)[1].split("</form>", 1)[0]
    assert "<input" not in form


def test_the_outcome_page_words_a_duplicate_apart_from_a_send() -> None:
    """ADR 0090 section 4's ``duplicate`` queued NOTHING. Reporting it as a send is the same lie as
    answering a refusal with the success response."""
    sent = str(message_resend_done("m1", "OB2", "archive", duplicate=False))
    dup = str(message_resend_done("m1", "OB2", "archive", duplicate=True))
    assert "Resend queued" in sent and "nothing new was queued" not in sent
    assert "Already resent" in dup and "nothing new was queued" in dup
    assert "Resend queued" not in dup


def test_the_outcome_page_carries_the_tail_warning_too() -> None:
    """The operator sees it when they decide AND when it lands. The confirm page's copy is read before
    the act; this one is what they still have in front of them if a delivery arrives out of order."""
    assert str(text(RESEND_TAIL_WARNING)) in str(
        message_resend_done("m1", "OB2", "archive", duplicate=False)
    )


def test_the_outcome_page_leaves_by_link_not_by_redirect() -> None:
    """Both ways out are anchors. A 303 to the message detail page would need ``messages:view_raw``,
    which a resend-only role does not hold -- the measured defect this page replaced. A link that
    role cannot follow is merely a link it does not click."""
    html = str(message_resend_done("m1", "OB2", "archive", duplicate=False))
    assert '<a href="/ui/messages/m1" class="btn-link">' in html
    assert '<a href="/ui/messages" class="btn-link">' in html


def test_the_confirm_page_holds_a_crafted_id_inside_its_path_segment() -> None:
    """This page is the ONE /ui/messages site whose id was not read back from a lookup (it reads no
    message at all), so a crafted value does reach the render. ``_seg`` keeps a ``?`` or ``#`` from
    starting a query or truncating the action URL."""
    html = str(message_resend_confirm("m1?x=1", "OB", "archive", "k1"))
    assert "/ui/messages/m1%3Fx%3D1" in html
    assert "/ui/messages/m1?x=1" not in html


# --- the routes ------------------------------------------------------------------------------------


async def _service(engine: Engine, *, step_up_max_age: int = 300) -> AuthService:
    service = AuthService(
        engine.store,
        AuthSettings(require_mfa=False, step_up_max_age_seconds=step_up_max_age),
    )
    await service.initialize()
    return service


async def _add(
    service: AuthService, username: str, *role_ids: str, channels: list[str] | None = None
) -> str:
    user_id = await service.create_local_user(
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=list(role_ids),
        actor="test",
    )
    # Applied BEFORE the first login: set_channel_scope revokes the user's sessions.
    await service.set_channel_scope(
        user_id, [ALL_CHANNELS] if channels is None else channels, actor="test"
    )
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id, password_hash=user.password_hash, must_change_password=False
    )
    return user_id


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(engine, auth=service, serve_ui=True))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def _login(c: httpx.AsyncClient, username: str) -> None:
    r = await c.post("/ui/login", data={"username": username, "password": PW})
    assert r.status_code in (200, 303), r.text


async def _seed(engine: Engine) -> str:
    """A PROCESSED message with one stored delivery to ``archive`` -- the resend SOURCE."""
    return await engine.store.enqueue_message(
        channel_id="ch1",
        raw=ADT,
        deliveries=[("archive", ADT)],
        control_id="MSG1",
        message_type="ADT^A01",
        source_type="file",
    )


def _registry(tmp_path: Path) -> Registry:
    """A graph carrying ONLY the alternate outbound the resend targets.

    The neighbouring suites' registries also declare an inbound plus a router and handler, and every
    one of those is inert here: ``_seed`` writes to the store directly, and a resend inserts an
    outbound-stage row without routing or transforming (ADR 0090 section 2). Carrying them would
    start a file poller, a router worker and a transform worker for a lane that never receives a
    message, on every ``engine.start()`` test in this file."""
    (tmp_path / "ob2").mkdir(exist_ok=True)
    reg = Registry()
    reg.add_outbound(
        OutboundConnection(
            "OB2", ConnectionSpec(ConnectorType.FILE, {"directory": str(tmp_path / "ob2")})
        )
    )
    return reg


async def _post_resend(
    c: httpx.AsyncClient, mid: str, *, to: str = "OB2", source: str = "archive", key: str = "k1"
) -> httpx.Response:
    return await c.post(
        f"/ui/messages/{mid}/resend?to={to}&source={source}&idempotency_key={key}",
        headers={"Sec-Fetch-Site": "same-origin"},
    )


async def test_the_console_resend_queues_a_delivery_and_audits_it(
    engine: Engine, tmp_path: Path
) -> None:
    """End to end over the cookie flow: the detail page offers the form, the confirm page carries the
    selection, and the POST reaches the SAME audited engine handler the JSON route does."""
    engine.add_registry(_registry(tmp_path))
    await engine.start()
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR.value)
    mid = await _seed(engine)
    async with _client(engine, service) as c:
        await _login(c, "op")
        detail = await c.get(f"/ui/messages/{mid}")
        assert detail.status_code == 200
        assert f'action="/ui/messages/{mid}/resend-confirm"' in detail.text

        confirm = await c.get(f"/ui/messages/{mid}/resend-confirm?to=OB2&source=archive")
        assert confirm.status_code == 200
        assert RESEND_TAIL_WARNING in confirm.text
        # The key is minted per render, so it is in the action URL and nowhere the operator typed.
        assert "idempotency_key=" in confirm.text

        r = await _post_resend(c, mid)
        assert r.status_code == 200
        assert "Resend queued" in r.text
        assert "queued to “OB2”" in r.text
        assert str(text(RESEND_TAIL_WARNING)) in r.text

    rows = [a for a in await engine.store.list_audit() if a["action"] == "message_resend"]
    assert len(rows) == 1
    detail_json = str(rows[0]["detail"] or "")
    assert '"to": "OB2"' in detail_json and '"from": "archive"' in detail_json
    assert "DOE^JANE" not in detail_json and "MSH|" not in detail_json


async def test_a_repeat_under_the_same_key_says_so_instead_of_claiming_a_send(
    engine: Engine, tmp_path: Path
) -> None:
    """ADR 0090 section 4: the key makes a retry a no-op, and the console carries a per-RENDER key so a
    double-submit of one confirm page cannot double-deliver.

    THE SECOND ANSWER MUST NOT READ LIKE THE FIRST. Both used to be a bare 303 to the same URL, so an
    operator who refreshed was told twice that a delivery was queued when the second queued nothing --
    the same lie this module refuses to tell on a refusal. The audit is the control: the endpoint
    writes a row only on a real ``resent``."""
    engine.add_registry(_registry(tmp_path))
    await engine.start()
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR.value)
    mid = await _seed(engine)
    async with _client(engine, service) as c:
        await _login(c, "op")
        first = await _post_resend(c, mid)
        assert first.status_code == 200 and "Resend queued" in first.text
        second = await _post_resend(c, mid)  # same key
        assert second.status_code == 200
        assert "Already resent" in second.text
        assert "nothing new was queued" in second.text
        assert "Resend queued" not in second.text
    rows = [a for a in await engine.store.list_audit() if a["action"] == "message_resend"]
    assert len(rows) == 1


async def test_an_unknown_message_is_refused_in_place_with_fixed_text(engine: Engine) -> None:
    """A refusal must NOT answer with the success response, and must not need a permission the
    resending role may lack. It re-renders the confirm page at 400 carrying one module-fixed notice;
    the caller's own outbound name and the engine's quoting ``detail`` travel nowhere."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR.value)
    async with _client(engine, service) as c:
        await _login(c, "op")
        r = await _post_resend(c, "no-such-message")
        assert r.status_code == 400
        assert str(text(RESEND_MISSING_NOTICE)) in r.text
        assert "Resend queued" not in r.text
        # The retry is offered with a FRESH key, so it is not mistaken for a duplicate.
        assert "idempotency_key=k1" not in r.text


async def test_a_malformed_name_is_not_reported_as_a_missing_connection(engine: Engine) -> None:
    """Nothing was looked up: the value failed the connection-name rule before any store or registry
    read. Reusing the 404 text would send the operator hunting on /ui/connections for a connection
    whose real problem is that the name could not name one."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR.value)
    mid = await _seed(engine)
    async with _client(engine, service) as c:
        await _login(c, "op")
        # URL-safe, so it reaches the route intact, and rejected by CONNECTION_NAME_PATTERN, which
        # requires a leading LETTER. A value with a space would never have got past the request line.
        r = await _post_resend(c, mid, to="9nosuchprefix")
        assert r.status_code == 400
        assert str(text(RESEND_MALFORMED_NOTICE)) in r.text
        assert str(text(RESEND_MISSING_NOTICE)) not in r.text
        # The operator's own typo IS shown back -- that is the page they are standing on, and seeing
        # it is how they spot the mistake. What must not appear is a pydantic structured echo or the
        # engine's quoting `detail`, which is where a value other than their own could come from.
        assert '"input"' not in r.text and "string_pattern_mismatch" not in r.text


async def test_a_denied_target_is_reported_as_denied_rather_than_missing(engine: Engine) -> None:
    """The engine answers 403 for a target outbound outside the caller's channel scope and 404 for one
    that does not exist. Collapsing them would tell a scoped operator to go looking for a connection
    that is there."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR.value, channels=["ch1"])
    mid = await _seed(engine)
    async with _client(engine, service) as c:
        await _login(c, "op")
        r = await _post_resend(c, mid, to="OB2")
        assert r.status_code == 400
        assert str(text(RESEND_DENIED_NOTICE)) in r.text
        assert str(text(RESEND_MISSING_NOTICE)) not in r.text


async def test_a_target_that_cannot_take_a_delivery_is_reported_as_blocked(
    engine: Engine, tmp_path: Path
) -> None:
    """The engine is deliberately NOT started, so OB2 is REGISTERED but not running -- ADR 0090 section
    7's silent-drop guard. It is one of several engine refusals that arrive as 409, which is why the
    notice names common causes without claiming the list is closed."""
    engine.add_registry(_registry(tmp_path))
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR.value)
    mid = await _seed(engine)
    async with _client(engine, service) as c:
        await _login(c, "op")
        r = await _post_resend(c, mid, to="OB2")
        assert r.status_code == 400
        assert str(text(RESEND_BLOCKED_NOTICE)) in r.text


def test_the_409_notice_makes_no_completeness_claim() -> None:
    """CLAUDE.md section 11 / SDS-3.6. Several distinct engine refusals arrive as one 409 and this
    module cannot tell them apart, so the notice must not read as a closed list -- it already missed
    ``ResendKeyConflict`` once, and an operator who checks every named cause and finds nothing wrong
    is worse off than one told the list is partial."""
    assert "Common causes" in RESEND_BLOCKED_NOTICE
    for closed in ("the cause is", "either", "must be", "only"):
        assert closed not in RESEND_BLOCKED_NOTICE.lower()


async def test_the_resend_lane_stands_on_messages_resend_alone(engine: Engine) -> None:
    """THE PERMISSION DECISION, pinned in both directions (ADR 0090 section 4 / CLAUDE.md section 9).

    The edit verbs next door require ``messages:edit`` AND ``messages:view_raw`` with ``phi=True``
    because the editor DISPLAYS the body it edits (BACKLOG #324). A resend does not: it re-transmits
    stored bytes and renders none, so copying that pair here would charge the per-actor PHI budget for
    a surface that emits nothing and would refuse a role deliberately narrowed to resend-without-read.

    The narrow role below is the whole point, and it is also the only FALSIFIABLE evidence that the
    confirm page reads no message: ``core.get_message`` writes a ``message_view`` audit row on every
    call, so a confirm page that reached it would leave one behind AND would 403 this role. Asserting
    the absence of the row on a page-builder call could not fail -- that builder takes four strings
    and never sees a MessageDetail."""
    service = await _service(engine)
    role = await service.create_custom_role(
        display_name="Resender",
        description=None,
        permissions=[Permission.MESSAGES_RESEND.value, Permission.MESSAGES_READ.value],
        actor="test",
    )
    await _add(service, "narrow", role.id)
    await _add(service, "viewer", Role.VIEWER.value)
    mid = await _seed(engine)
    app = create_app(engine, auth=service, serve_ui=True)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        await _login(c, "narrow")
        ok = await c.get(f"/ui/messages/{mid}/resend-confirm?to=OB2&source=archive")
        assert ok.status_code == 200
        assert str(text(RESEND_TAIL_WARNING)) in ok.text
        # Same session, same message: the raw-body page IS refused.
        assert (await c.get(f"/ui/messages/{mid}")).status_code == 403
        # AND THE OUTCOME STILL REACHES THIS ROLE. Redirecting to that 403 page was the measured
        # defect the in-place answer fixes: every outcome, success and refusal alike, arrived as raw
        # JSON this operator could not read. No registry here, so the POST refuses -- legibly.
        refused = await _post_resend(c, mid, to="OB2")
        assert refused.status_code == 400
        assert str(text(RESEND_MISSING_NOTICE)) in refused.text
        assert "forbidden" not in refused.text
    # Nothing read the message. The refused detail GET above cannot have written one either, so this
    # covers the confirm page specifically.
    assert not [a for a in await engine.store.list_audit() if a["action"] == "message_view"]
    # A fresh cookie jar on the SAME app -- only the session must differ, not the route table.
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        await _login(c, "viewer")
        assert (
            await c.get(f"/ui/messages/{mid}/resend-confirm?to=OB2&source=archive")
        ).status_code != 200


async def test_a_stale_step_up_reopens_the_confirm_page_with_the_selection(engine: Engine) -> None:
    """A body-carrying POST cannot be auto-retried, and this one is body-LESS only because the
    selection rides the query. So the re-auth is pointed at the CONFIRM page carrying ``to`` and
    ``source`` -- the operator is not stranded mid-task -- while the stale ``idempotency_key`` is
    dropped, because the confirm page mints a fresh one and the attempt behind the old key never ran."""
    service = await _service(engine, step_up_max_age=-1)
    await _add(service, "op", Role.OPERATOR.value)
    mid = await _seed(engine)
    async with _client(engine, service) as c:
        await _login(c, "op")
        r = await _post_resend(c, mid)
        assert r.status_code == 303
        location = r.headers["location"]
        assert location.startswith("/ui/reauth?next=")
        nxt = unquote(dict(parse_qsl(urlsplit(location).query))["next"])
        assert nxt.startswith(f"/ui/messages/{mid}/resend-confirm?")
        params = dict(parse_qsl(urlsplit(nxt).query))
        assert params == {"to": "OB2", "source": "archive"}
        assert "idempotency_key" not in nxt


async def test_the_longest_accepted_names_still_fit_the_reauth_continuation(
    engine: Engine,
) -> None:
    """THE BOUND THAT MADE THIS ROUTE'S OWN LIMITS DISAGREE WITH THE RE-AUTH PAGE'S.

    ``_reauth_redirect`` packs the whole continuation into ``GET /ui/reauth``'s ``next``, which is
    ``Query(max_length=512)``, and ``quote()`` expands every ``=`` and ``&`` to three characters. At
    the connection-name rule's own 256 ceiling this route built a 542-character ``next`` and the
    re-auth page answered a raw 422 -- a dead end with the selection gone. ``_RESEND_NAME_MAX`` is
    what keeps the two agreeing, so drive the WORST case this route will accept and follow it.

    MEASURED WHILE WRITING THIS, and it bounds what the cap buys: FastAPI solves DEPENDENCIES before
    it validates a route's own ``Query`` params, so on a stale window ``reauth_next`` sees the raw
    query and the cap has not run yet. The cap therefore guarantees that every value this route
    DECLARES legal survives the continuation -- it does not stop an over-long one from being read by
    the lambda. An over-long name still ends at a 422; the cap moves it to the POST, where a fresh
    window rejects it, instead of leaving a legal value dead-ending at the re-auth page."""
    service = await _service(engine, step_up_max_age=-1)
    await _add(service, "op", Role.OPERATOR.value)
    mid = await _seed(engine)
    longest = "A" * _RESEND_NAME_MAX
    async with _client(engine, service) as c:
        await _login(c, "op")
        r = await _post_resend(c, mid, to=longest, source=longest)
        assert r.status_code == 303
        follow = await c.get(r.headers["location"])
        # The re-auth page renders; it does not 422 on a `next` this route was willing to build.
        assert follow.status_code == 200, follow.text
    # One over the ceiling is refused by THIS route. A FRESH window, because a stale one short-
    # circuits at the dependency before the Query bound is reached (see the docstring).
    fresh = await _service(engine)
    await _add(fresh, "op2", Role.OPERATOR.value)
    async with _client(engine, fresh) as c:
        await _login(c, "op2")
        over = await _post_resend(c, mid, to="A" * (_RESEND_NAME_MAX + 1), source="archive")
        assert over.status_code == 422
