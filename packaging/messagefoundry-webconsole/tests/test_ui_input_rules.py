# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1740: the /ui routes applied none of the rules ``messagefoundry/api/validation.py``
defines, because the console calls the engine handlers BY REFERENCE and a direct call runs no
request validation.

These are the BEHAVIOURAL half: each route this change touches actually refuses, and each refusal
is paired with a positive control so a gate broken to deny everything fails here rather than
passing by lockout. Two tests assert EQUIVALENCE WITH THE JSON TWIN against the same input, so the
seam is an executable claim and a future drift between the two surfaces fails a test.

The DECLARATIVE half is elsewhere on purpose: ``test_golden_surface.py`` pins which rule each /ui
parameter carries, next to the two goldens that pin the route table and the step-up registry, so all
three are derived from one mount and cannot disagree about which routes exist.

The two halves guard different failures and neither is sufficient alone. The golden catches a rule
renamed, swapped or dropped from a DECLARATION. Only these tests catch a rule still declared and no
longer running -- deleting a ``check_filters`` call leaves the golden green.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
from _ui_clients import (
    SAME_ORIGIN,
    auth_service,
    bearer,
    cookie_login,
    provision,
    seed_message,
    ui_client,
)

from messagefoundry.auth import Role
from messagefoundry.pipeline import Engine
from messagefoundry_webconsole.routes._common import FILTER_RULES

#: A connection name the rule refuses, in the way an operator most plausibly produces one: a space.
#: It is also the shape that matters most, since a name is what reaches a store query and a log line.
BAD_NAME = "IB ACME ADT"

#: What the console says for each refused rule, as a substring stable enough to assert on.
NAME_REFUSAL = "a connection name is a letter"
STATUS_REFUSAL = "a status is one word"
KIND_REFUSAL = "an event kind is one word"
PRINTABLE_REFUSAL = "printable text with no control characters"


@pytest.fixture
async def admin(engine: Engine) -> AsyncIterator[httpx.AsyncClient]:
    """A browser client signed in as an ADMINISTRATOR.

    The widest built-in role, because the routes under test span messages, monitoring and the
    step-up-gated purge surface, and every test here is about INPUT rather than authz -- a
    narrower role would make a refusal ambiguous between the two.
    """
    service = await auth_service(engine)
    await provision(service, "adm", [Role.ADMINISTRATOR.value])
    async with ui_client(engine, service) as c:
        await cookie_login(c, "adm")
        yield c


def test_each_rule_refuses_something_and_accepts_something() -> None:
    """Every rule discriminates.

    The control for everything below: a rule that accepted everything would pass each refusal test
    by doing nothing, and one that refused everything would pass by locking the page. Pinned against
    the live rule tuple, so a rule added without a case here fails rather than going unmeasured.
    """
    cases = {
        "connection": ("IB_ACME_ADT", BAD_NAME),
        "status": ("PROCESSED", "ADT^A01"),
        "event kind": ("idle_timeout", "idle timeout"),
        "message type": ("ADT^A01", "ADT\x00A01"),
        "control id": ("MSG1", "MSG\r1"),
    }
    assert sorted(cases) == sorted(r.name for r in FILTER_RULES), (
        "a rule was added or removed from routes/_common without a case here"
    )
    for rule in FILTER_RULES:
        good, bad = cases[rule.name]
        assert rule.adapter.validate_python(good) == good
        with pytest.raises(ValueError):
            rule.adapter.validate_python(bad)


# --- the message log --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("field", "value", "refusal"),
    [
        ("channel_id", BAD_NAME, NAME_REFUSAL),
        ("status", "ADT^A01", STATUS_REFUSAL),
        ("message_type", "ADT\x00A01", PRINTABLE_REFUSAL),
        ("control_id", "MSG\r1", PRINTABLE_REFUSAL),
    ],
)
async def test_message_log_refuses_a_filter_the_json_route_refuses(
    engine: Engine, admin: httpx.AsyncClient, field: str, value: str, refusal: str
) -> None:
    """400 plus the filter form carrying the banner. Pre-fix each of these reached the store query,
    which is what the JSON /messages route has always refused with a 422."""
    await seed_message(engine)
    r = await admin.get("/ui/messages", params={field: value})
    assert r.status_code == 400
    assert refusal in r.text
    # No results TABLE, rather than "MSG1 is absent": the seeded control id is MSG1, and the refused
    # `MSG\rl` echoes back as MSG1 once for_echo strips the CR, so a bare substring check would read
    # a correctly-refused request as a leaked result row.
    assert "<table" not in r.text


async def test_message_log_refusal_matches_the_json_route(admin: httpx.AsyncClient) -> None:
    """The parity claim, measured on BOTH surfaces against the same input: the console 400s exactly
    where the JSON route 422s. That is the seam written as an executable claim -- a future drift
    between the two fails a test instead of going unnoticed."""
    headers = await bearer(admin, "adm")
    for field, value in (("channel_id", BAD_NAME), ("status", "ADT^A01")):
        json_twin = await admin.get("/messages", params={field: value}, headers=headers)
        console = await admin.get("/ui/messages", params={field: value})
        assert (json_twin.status_code, console.status_code) == (422, 400), (field, value)


async def test_message_log_still_filters_on_a_valid_value(
    engine: Engine, admin: httpx.AsyncClient
) -> None:
    """Positive control: a value every rule accepts is still APPLIED -- present when it matches the
    seeded row, absent when it does not."""
    await seed_message(engine)
    hit = await admin.get("/ui/messages", params={"channel_id": "ch1", "control_id": "MSG1"})
    assert hit.status_code == 200 and "MSG1" in hit.text
    miss = await admin.get("/ui/messages", params={"channel_id": "ch2"})
    assert miss.status_code == 200 and "MSG1" not in miss.text


async def test_the_received_date_bounds_still_refuse_their_own_way(
    engine: Engine, admin: httpx.AsyncClient
) -> None:
    """The two refusals on this one form do not interfere. BACKLOG #1744 gave the date bounds their
    own 400 re-render with a different sentence; adding four more checked fields to the same handler
    must not make a bad DATE report a bad FILTER, or the other way round."""
    await seed_message(engine)
    bad_date = await admin.get("/ui/messages", params={"received_from": "not-a-date"})
    assert bad_date.status_code == 400
    assert "received-date bounds" in bad_date.text
    assert NAME_REFUSAL not in bad_date.text
    bad_name = await admin.get("/ui/messages", params={"channel_id": BAD_NAME})
    assert bad_name.status_code == 400
    assert NAME_REFUSAL in bad_name.text
    assert "received-date bounds" not in bad_name.text


# --- the event log ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("field", "value", "refusal", "echoed"),
    [
        ("connection", BAD_NAME, NAME_REFUSAL, True),
        # `kind` is a select over a closed vocabulary, so an off-vocabulary value matches no option
        # and comes back unselected. That is the right render -- there is no option to carry it --
        # and the operator re-picks from the dropdown rather than correcting text.
        ("kind", "idle timeout", KIND_REFUSAL, False),
    ],
)
async def test_event_log_refuses_a_filter_the_json_route_refuses(
    admin: httpx.AsyncClient, field: str, value: str, refusal: str, echoed: bool
) -> None:
    """400 plus the event filter form carrying the banner, for both of its filters."""
    r = await admin.get("/ui/events", params={field: value})
    assert r.status_code == 400
    assert refusal in r.text
    assert (value in r.text) is echoed
    assert "No events." not in r.text  # never phrased as an empty RESULT


async def test_event_log_still_renders_for_a_valid_filter(admin: httpx.AsyncClient) -> None:
    """Positive control for the two refusals above: the filter runs, and this store has no events."""
    r = await admin.get("/ui/events", params={"connection": "IB_ACME_ADT", "kind": "idle_timeout"})
    assert r.status_code == 200
    assert "No events." in r.text


# --- content search ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("field", "value", "refusal"),
    [("channel_id", BAD_NAME, NAME_REFUSAL), ("status", "ADT^A01", STATUS_REFUSAL)],
)
async def test_content_search_form_refuses_a_filter_the_json_route_refuses(
    admin: httpx.AsyncClient, field: str, value: str, refusal: str
) -> None:
    """The content-search GET form, 400 plus its own banner. Its POST arm already applied these four
    rules through ``SearchPresetCriteria``; only the GET arm carried none."""
    r = await admin.get("/ui/messages/search", params={field: value})
    assert r.status_code == 400
    assert refusal in r.text


async def test_content_search_form_still_renders_for_a_valid_filter(
    admin: httpx.AsyncClient,
) -> None:
    """Positive control: a valid filter with no needle still renders the bare form, 200."""
    r = await admin.get("/ui/messages/search", params={"channel_id": "IB_ACME_ADT"})
    assert r.status_code == 200
    assert "IB_ACME_ADT" in r.text


# --- the routes whose values the console mints ---------------------------------------------------


@pytest.mark.parametrize("field", ["channel_id", "destination_name"])
async def test_dead_letters_refuses_a_bad_connection_name(
    admin: httpx.AsyncClient, field: str
) -> None:
    """422, not a re-render: this page carries no filter form, so both values arrive only from a
    link the console built and there is nothing an operator typed to hand back."""
    r = await admin.get("/ui/dead-letters", params={field: BAD_NAME})
    assert r.status_code == 422


async def test_dead_letters_still_renders_for_a_valid_connection_name(
    admin: httpx.AsyncClient,
) -> None:
    """Positive control for the two 422s above."""
    r = await admin.get("/ui/dead-letters", params={"channel_id": "IB_ACME_ADT"})
    assert r.status_code == 200


@pytest.mark.parametrize("action", ["start", "stop", "restart", "purge/all"])
async def test_per_name_control_refuses_a_bad_connection_name(
    admin: httpx.AsyncClient, action: str
) -> None:
    """422 on the path segment, before the handler runs. Only a hand-built URL gets here: the console
    renders these names into form actions out of the live registry."""
    r = await admin.post(f"/ui/connections/{BAD_NAME}/{action}", headers=SAME_ORIGIN)
    assert r.status_code == 422


@pytest.mark.parametrize("action", ["start", "stop", "restart"])
async def test_per_name_control_reaches_the_handler_for_a_valid_name(
    admin: httpx.AsyncClient, action: str
) -> None:
    """Positive control: a well-formed name passes the rule and reaches the control handler, which
    404s a connection this engine does not have. NOT 422 is the whole assertion -- a gate broken to
    refuse every name would answer 422 here too."""
    r = await admin.post(f"/ui/connections/IB_NOT_REGISTERED/{action}", headers=SAME_ORIGIN)
    assert r.status_code != 422


async def test_purge_confirm_never_arms_a_name_no_outbound_has(admin: httpx.AsyncClient) -> None:
    """``dest`` is the one name on this surface left unannotated, so this is what guards it instead.

    The handler intersects the requested ``dest`` with ``rr.outbound_quiesced(d)``, which admits only
    live outbound names -- strictly narrower than the connection-name rule, so nothing is lost. The
    audit test below is why the annotation came off again.
    """
    for dest in (BAD_NAME, "OB_NOT_REGISTERED"):
        r = await admin.get("/ui/connections/purge-confirm", params={"dest": dest})
        assert r.status_code == 200
        assert dest not in r.text, f"{dest!r} must not be pre-armed for purge"


# --- the two capture-and-continue batches --------------------------------------------------------


async def test_bulk_control_refuses_one_name_without_aborting_the_batch(
    admin: httpx.AsyncClient,
) -> None:
    """``ui_bulk_control`` reads its names out of the POST BODY, so there is no parameter to annotate
    and a raise would fail the whole operation over one forged selection. The bad row becomes an
    OUTCOME and the good row is still attempted.

    These two tests are the ONLY guard on these routes: the golden table is built from FastAPI's
    parameter list, and a body-reading route contributes no rows to it.
    """
    from messagefoundry_webconsole.pages.connections import _b64url

    def sel(name: str) -> str:
        # The console's own row-key encoding, so the selections decode exactly as a browser's would
        # and the refusal under test is the NAME rule rather than a malformed key.
        return f"source|{_b64url(name)}|{_b64url('')}"

    body = {"action": "start", "sel": [sel(BAD_NAME), sel("IB_NOT_REGISTERED")]}
    r = await admin.post("/ui/connections/bulk-control", data=body, headers=SAME_ORIGIN)
    assert r.status_code == 200
    assert "not applied: not a valid connection name" in r.text
    assert BAD_NAME not in r.text  # the refused value is never reflected onto the result table
    assert "2 target(s) processed" in r.text  # the good selection was still attempted


async def test_purge_bulk_refuses_one_dest_without_aborting_the_batch(
    admin: httpx.AsyncClient,
) -> None:
    """The same shape on the bulk purge, whose ``dest`` values ride the body as plain form fields --
    and which, pre-fix, echoed an unvalidated one straight onto its own result table."""
    r = await admin.post(
        "/ui/connections/purge-bulk",
        data={"scope": "all", "dest": [BAD_NAME, "OB_NOT_REGISTERED"]},
        headers=SAME_ORIGIN,
    )
    assert r.status_code == 200
    assert "not applied: not a valid connection name" in r.text
    assert BAD_NAME not in r.text
    assert "2 destination(s) processed" in r.text


# --- what an empty filter box means, and what a refusal is allowed to echo -----------------------
#
# Three defects the xhigh review found and this suite now pins. All three were reachable from the
# ordinary path -- a browser submits every box in a GET filter form, empty ones included -- and none
# of them were visible to the golden table, which sees declarations rather than behaviour.


async def test_a_blank_filter_box_is_no_filter_and_not_a_match_on_the_empty_string(
    engine: Engine, admin: httpx.AsyncClient
) -> None:
    """The message log must answer the same with a blank box as without it.

    MEASURED before the fix: ``?channel_id=ch1&status=&message_type=&control_id=`` returned 200 with
    the seeded row ABSENT, because the store's filter builder binds any value that is not None and
    "" became a literal equality test. An operator reads that empty page as an empty store.
    """
    await seed_message(engine)
    blanks = {"status": "", "message_type": "", "control_id": ""}
    hit = await admin.get("/ui/messages", params={"channel_id": "ch1", **blanks})
    assert hit.status_code == 200 and "MSG1" in hit.text
    all_blank = await admin.get("/ui/messages", params={"channel_id": "", **blanks})
    assert all_blank.status_code == 200 and "MSG1" in all_blank.text
    # The control: a REAL filter value that does not match still excludes the row, so the fix did
    # not simply stop filtering.
    miss = await admin.get("/ui/messages", params={"channel_id": "ch2", **blanks})
    assert miss.status_code == 200 and "MSG1" not in miss.text


async def test_a_blank_search_filter_is_no_filter(engine: Engine, admin: httpx.AsyncClient) -> None:
    """The same on the content-search GET arm, which had no blank normalisation of its own."""
    await seed_message(engine)
    r = await admin.get(
        "/ui/messages/search", params={"field_path": "MSH-9", "channel_id": "", "status": ""}
    )
    assert r.status_code == 200 and "MSG1" in r.text


async def test_a_blank_connection_box_does_not_deny_a_channel_scoped_operator(
    engine: Engine,
) -> None:
    """A blank connection box must not read as a request for the channel named "".

    MEASURED before the fix: a channel-scoped operator submitting the event filter form with the
    connection box empty got 403 AND an ``auth.channel_denied`` audit row naming them and their
    host. A security record of an attempt nobody made, generated by using the page normally.
    """
    service = await auth_service(engine)
    user_id = await provision(service, "scoped", [Role.OPERATOR.value])
    await service.set_channel_scope(user_id, ["ch1"], actor="test")
    async with ui_client(engine, service) as c:
        await cookie_login(c, "scoped")
        assert (await c.get("/ui/events")).status_code == 200  # control: no query at all
        assert (await c.get("/ui/events", params={"connection": "", "kind": ""})).status_code == 200
    denied = [r for r in await engine.store.list_audit(limit=200) if r["action"].endswith("denied")]
    assert denied == [], f"the filter form wrote a false denial row: {denied}"


@pytest.mark.parametrize(
    ("field", "value", "forbidden"),
    [("message_type", "ADT\x00A01", "\x00"), ("control_id", "MSG\r1", "\r")],
)
async def test_a_refused_control_character_is_not_echoed_into_the_response(
    admin: httpx.AsyncClient, field: str, value: str, forbidden: str
) -> None:
    """The refusal page must not re-emit the byte the rule just rejected.

    MEASURED before the fix: the NUL and the CR came back in the response body. Markup escaping does
    not cover them, and the whole reason ``api/validation.py`` refuses them is that one forges a
    record in anything that reads a line at a time -- which the refusal page then handed back out.
    The banner still explains what was wrong, so the operator loses nothing.
    """
    r = await admin.get("/ui/messages", params={field: value})
    assert r.status_code == 400
    assert PRINTABLE_REFUSAL in r.text
    assert forbidden not in r.text


async def test_the_event_refusal_renders_no_results_table_at_all(admin: httpx.AsyncClient) -> None:
    """Not even the table's header row: the filter never ran, so any table under the banner reads as
    its result. Suppressing only the "No events." line left the headers behind."""
    r = await admin.get("/ui/events", params={"connection": BAD_NAME})
    assert r.status_code == 400 and NAME_REFUSAL in r.text
    assert "<table" not in r.text
    ok = await admin.get("/ui/events")  # control: the table is there when the filter did run
    assert ok.status_code == 200 and "<table" in ok.text


async def test_the_flag_route_refuses_a_bad_connection_name(admin: httpx.AsyncClient) -> None:
    """The fifth per-name route, and the only one that WRITES -- it reaches the comment-preserving
    connections.toml writer, so it is the last one that should have been left unruled."""
    r = await admin.post(
        f"/ui/connections/{BAD_NAME}/flag",
        data={"direction": "inbound", "flagged": "true"},
        headers=SAME_ORIGIN,
    )
    assert r.status_code == 422
    ok = await admin.post(
        "/ui/connections/IB_NOT_REGISTERED/flag",
        data={"direction": "inbound", "flagged": "true"},
        headers=SAME_ORIGIN,
    )
    assert ok.status_code != 422  # control: a well-formed name reaches the handler


async def test_purge_confirm_still_audits_a_channel_scoped_attempt_with_a_bad_dest(
    engine: Engine,
) -> None:
    """``dest`` is deliberately NOT annotated, and this is why.

    FastAPI validates a query parameter before the handler body, so a 422 would return before the
    channel-scope branch that writes the denial row. MEASURED while it was annotated: a malformed
    dest gave 422 and ZERO audit rows, where a well-formed one gives 403 and a row naming the
    operator -- an attacker could drop their own security event by sending a bad name.
    """
    service = await auth_service(engine)
    user_id = await provision(service, "scoped", [Role.OPERATOR.value])
    await service.set_channel_scope(user_id, ["ch1"], actor="test")
    async with ui_client(engine, service) as c:
        await cookie_login(c, "scoped")
        r = await c.get("/ui/connections/purge-confirm", params={"dest": BAD_NAME})
        assert r.status_code == 403
    denied = [r for r in await engine.store.list_audit(limit=200) if r["action"].endswith("denied")]
    assert len(denied) == 1, f"the attempt must still be audited: {denied}"
