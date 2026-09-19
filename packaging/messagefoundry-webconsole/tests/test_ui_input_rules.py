# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1740: the /ui routes applied none of the rules ``messagefoundry/api/validation.py``
defines, because the console calls the engine handlers BY REFERENCE and a direct call runs no
request validation.

Two halves, and they guard different failures.

* **A golden input-rule table.** Every string path/query parameter on every mounted /ui route, with
  the ``api.validation`` rule it carries and how a refusal is shaped. The table is DERIVED -- the
  rule column is resolved by matching each parameter's own JSON-schema constraint against the
  schemas of the rules ``routes/_common`` holds, and the body-checked rows are read from the same
  ``UI_BODY_FILTER_RULES`` mapping the routes execute from. Nothing here is transcribed, so a table
  that agrees with a route which has stopped applying a rule cannot be written.
* **Behavioural refusal tests**, one per route this change touches, each paired with a positive
  control. The golden cannot see whether a body-checked route still CALLS ``check_filters``; these
  can, and only these can.

Said plainly, because the pairing is the whole claim: the golden catches a rule that was renamed,
swapped or dropped from a declaration, and the behavioural tests catch a rule that is still
declared and no longer runs. Neither is sufficient alone.

WHAT THE GOLDEN DOES NOT SEE, stated rather than left to be discovered. It is built from FastAPI's
parameter table, so a route that reads its values out of the request BODY contributes no rows at
all -- ``ui_bulk_control`` and ``ui_purge_bulk`` are absent from it, and their two behavioural tests
at the bottom of this file are the only guard they have.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Annotated, Any

import httpx
import pytest
from fastapi.routing import APIRoute
from pydantic import TypeAdapter

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from messagefoundry_webconsole.routes._common import _FILTER_RULES, UI_BODY_FILTER_RULES

_GOLDEN = Path(__file__).resolve().parent / "golden" / "ui_input_rules.txt"

PW = "a-strong-test-passphrase"  # >=15, no app/vendor terms -- satisfies the ASVS policy (WP-3)
ADT = "MSH|^~\\&|S|F|R|RF|20260604||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"
SFS = {"Sec-Fetch-Site": "same-origin"}

#: A connection name the rule refuses, in the way an operator most plausibly produces: a space. It
#: is also the shape that matters most, since a name is what reaches a store query and a log line.
BAD_NAME = "IB ACME ADT"

#: What the console says for each refused rule, as a substring stable enough to assert on.
NAME_REFUSAL = "a connection name is a letter"
STATUS_REFUSAL = "a status is one word"
KIND_REFUSAL = "an event kind is one word"
PRINTABLE_REFUSAL = "printable text with no control characters"


# --- half one: the golden input-rule table ---------------------------------------------------


def _string_schema(schema: dict[str, Any]) -> dict[str, Any] | None:
    """The string branch of a parameter's JSON schema, or ``None`` if it has none.

    A /ui parameter is rarely a bare string: ``X | None`` renders as ``anyOf`` and a repeated query
    value as ``array``. Digging to the string branch is what lets one comparison cover all three,
    and returning ``None`` for an int or a bool is how ``limit``/``offset``/``defer`` stay out of
    the table -- they are not data items these rules govern, and keeping them out also keeps this
    golden from churning on unrelated pager work.
    """
    if schema.get("type") == "string":
        return schema
    if schema.get("type") == "array":
        items = schema.get("items")
        return _string_schema(items) if isinstance(items, dict) else None
    for branch in schema.get("anyOf", []):
        if isinstance(branch, dict) and (found := _string_schema(branch)) is not None:
            return found
    return None


def _constraint(schema: dict[str, Any] | None) -> tuple[str | None, int | None]:
    """A string schema reduced to the pair that identifies a rule: its pattern and its ceiling."""
    if schema is None:
        return (None, None)
    max_length = schema.get("maxLength")
    return (schema.get("pattern"), max_length if isinstance(max_length, int) else None)


def _rules_by_constraint() -> dict[tuple[str | None, int | None], list[str]]:
    """Every rule ``routes/_common`` holds, indexed by the constraint it actually enforces.

    A LIST per constraint, not a single name. ``status`` and ``event kind`` are distinct rules that
    resolve to the same annotated type today, so an annotated parameter carrying that constraint is
    honestly ``event kind|status`` and not either one of them -- picking a winner would put an
    arbitrary tie-break into a table whose whole job is to be checkable.
    """
    index: dict[tuple[str | None, int | None], list[str]] = {}
    for name, (adapter, _sentence) in _FILTER_RULES.items():
        index.setdefault(_constraint(_string_schema(adapter.json_schema())), []).append(name)
    return {key: sorted(names) for key, names in index.items()}


def _input_rule_rows() -> list[str]:
    """The live table: ``METHOD path<TAB>param<TAB>where<TAB>rule<TAB>refusal``.

    ``rule`` is ``-`` where the parameter carries no rule this module defines, which is the honest
    reading and not a hidden gap: several /ui path ids are Limb B of BACKLOG #1740 and several query
    values are not control-plane data items at all. The ``-`` rows are IN the golden on purpose, so
    closing one of them is a visible diff rather than an invisible improvement.
    """
    app = create_app(None, serve_ui=True)
    by_constraint = _rules_by_constraint()
    rows: set[str] = set()
    for route in app.router.routes:
        if not isinstance(route, APIRoute) or not route.path.startswith("/ui"):
            continue
        method = sorted(route.methods)[0]
        body_rules = UI_BODY_FILTER_RULES.get(route.path, {})
        for where, fields in (
            ("path", route.dependant.path_params),
            ("query", route.dependant.query_params),
        ):
            for field in fields:
                info = field.field_info
                # Rebuild the parameter's effective type: FastAPI splits an ``Annotated`` alias into
                # an annotation plus metadata, and a ``Query(max_length=...)`` contributes metadata
                # with no annotation of its own. Only the pair carries the real constraint.
                annotation = (
                    Annotated[(info.annotation, *info.metadata)]
                    if info.metadata
                    else info.annotation
                )
                schema = _string_schema(TypeAdapter(annotation).json_schema())
                if schema is None:
                    continue
                # The ALIAS, not the python name: ``status_filter`` rides the wire as ``status``,
                # which is the key both the form and UI_BODY_FILTER_RULES use.
                name = field.alias or field.name
                declared = by_constraint.get(_constraint(schema))
                if declared:
                    rule, refusal = "|".join(declared), "422"
                elif name in body_rules:
                    rule, refusal = body_rules[name], "400-rerender"
                else:
                    rule, refusal = "-", "-"
                rows.add(f"{method} {route.path}\t{name}\t{where}\t{rule}\t{refusal}")
    return sorted(rows)


def _drift(golden: list[str]) -> tuple[list[str], list[str]]:
    """``(missing, unexpected)`` between the golden rows and the live table. Empty pairs agree."""
    live = _input_rule_rows()
    return sorted(set(golden) - set(live)), sorted(set(live) - set(golden))


def test_ui_input_rule_table_matches_golden() -> None:
    """The pinned table. A /ui parameter that loses its rule, gains a different one, or arrives with
    none at all diverges here -- including a NEW route, which lands as an unexpected ``-`` row."""
    golden = _GOLDEN.read_text(encoding="utf-8").splitlines()
    missing, unexpected = _drift(golden)
    assert (missing, unexpected) == ([], []), (
        "the /ui input-rule table drifted from tests/golden/ui_input_rules.txt -- if intentional, "
        "regenerate the golden; if not, a parameter lost or changed the rule it carries.\n"
        f"missing (in golden, not live): {missing}\n"
        f"unexpected (live, not golden): {unexpected}"
    )


def test_the_drift_check_can_return_the_other_answer() -> None:
    """The control. A comparison that passes on a doctored golden is measuring nothing."""
    golden = _GOLDEN.read_text(encoding="utf-8").splitlines()
    doctored = [row.replace("\tconnection\t422", "\t-\t-") for row in golden]
    missing, unexpected = _drift(doctored)
    assert missing and unexpected, "doctoring the rule column must be visible to the comparison"


def test_every_declared_body_rule_is_a_rule_that_exists() -> None:
    """A route may only name a rule ``_FILTER_RULES`` defines, and only on a path that is mounted.

    Both halves are typo guards the golden cannot give: a misspelled rule name raises ``KeyError``
    only when an operator happens to fill that field, and a misspelled route path silently means
    the route checks nothing at all.
    """
    app = create_app(None, serve_ui=True)
    mounted = {r.path for r in app.router.routes if isinstance(r, APIRoute)}
    for path, rules in UI_BODY_FILTER_RULES.items():
        assert path in mounted, f"{path} declares filter rules and is not a mounted route"
        unknown = sorted(set(rules.values()) - set(_FILTER_RULES))
        assert not unknown, f"{path} names rules that do not exist: {unknown}"


def test_each_rule_refuses_something_and_accepts_something() -> None:
    """Every rule discriminates. A rule that accepted everything would pass every behavioural test
    below by doing nothing, and a rule that refused everything would pass them by locking the page."""
    cases = {
        "connection": ("IB_ACME_ADT", BAD_NAME),
        "status": ("PROCESSED", "ADT^A01"),
        "event kind": ("idle_timeout", "idle timeout"),
        "message type": ("ADT^A01", "ADT\x00A01"),
        "control id": ("MSG1", "MSG\r1"),
    }
    assert sorted(cases) == sorted(_FILTER_RULES), "a rule was added or removed without a case here"
    for rule, (good, bad) in cases.items():
        adapter, _sentence = _FILTER_RULES[rule]
        assert adapter.validate_python(good) == good
        with pytest.raises(ValueError):
            adapter.validate_python(bad)


# --- half two: the routes actually refuse ------------------------------------------------------


async def _service(engine: Engine) -> AuthService:
    # require_mfa=False as elsewhere in this suite: these tests exercise input validation and the
    # fixtures never enroll an authenticator.
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    return service


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(engine, auth=service, serve_ui=True))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def _provision(service: AuthService, username: str, roles: list[str]) -> None:
    user_id = await service.create_local_user(
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=roles,
        actor="test",
    )
    # BACKLOG #1152: an unset channel scope DENIES; grant the estate explicitly.
    await service.set_channel_scope(user_id, [ALL_CHANNELS], actor="test")
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id, password_hash=user.password_hash, must_change_password=False
    )


@pytest.fixture
async def admin(engine: Engine) -> AsyncIterator[httpx.AsyncClient]:
    """A browser client signed in as an ADMIN -- the /ui purge and control routes this change
    touches need more than the operator role, and every test here is about input, not authz."""
    service = await _service(engine)
    await _provision(service, "adm", [Role.ADMINISTRATOR.value])
    async with _client(engine, service) as c:
        r = await c.post("/ui/login", data={"username": "adm", "password": PW})
        assert r.status_code in (200, 303)
        yield c


async def _seed_message(engine: Engine) -> str:
    return await engine.store.enqueue_message(
        channel_id="ch1",
        raw=ADT,
        deliveries=[("archive", ADT)],
        control_id="MSG1",
        message_type="ADT^A01",
        source_type="file",
    )


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
    """400 + the filter form carrying the banner. Pre-fix each of these reached the store query,
    which is what the JSON /messages route has always refused with a 422."""
    await _seed_message(engine)
    r = await admin.get("/ui/messages", params={field: value})
    assert r.status_code == 400
    assert refusal in r.text
    assert "MSG1" not in r.text  # and NOT searched under a filter the engine would not apply


async def test_message_log_refusal_matches_the_json_route(
    engine: Engine, admin: httpx.AsyncClient
) -> None:
    """The parity claim, measured on both surfaces against the SAME input: the console 400s exactly
    where the JSON route 422s. This is the seam as an executable claim -- a future drift between the
    two fails a test rather than going unnoticed."""
    token = (await admin.post("/auth/login", json={"username": "adm", "password": PW})).json()[
        "token"
    ]
    headers = {"Authorization": f"Bearer {token}"}
    for field, value in (("channel_id", BAD_NAME), ("status", "ADT^A01")):
        json_twin = await admin.get("/messages", params={field: value}, headers=headers)
        console = await admin.get("/ui/messages", params={field: value})
        assert (json_twin.status_code, console.status_code) == (422, 400), (field, value)


async def test_message_log_still_filters_on_a_valid_value(
    engine: Engine, admin: httpx.AsyncClient
) -> None:
    """Positive control: a value every rule accepts is still APPLIED -- present when it matches the
    seeded row, absent when it does not. A gate broken to deny everything fails here."""
    await _seed_message(engine)
    hit = await admin.get("/ui/messages", params={"channel_id": "ch1", "control_id": "MSG1"})
    assert hit.status_code == 200 and "MSG1" in hit.text
    miss = await admin.get("/ui/messages", params={"channel_id": "ch2"})
    assert miss.status_code == 200 and "MSG1" not in miss.text


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
    """400 + the event filter form carrying the banner, for both of its filters."""
    r = await admin.get("/ui/events", params={field: value})
    assert r.status_code == 400
    assert refusal in r.text
    assert (value in r.text) is echoed
    assert "No events." not in r.text  # never phrased as an empty RESULT


async def test_event_log_still_renders_for_a_valid_filter(admin: httpx.AsyncClient) -> None:
    """Positive control for the two refusals above."""
    r = await admin.get("/ui/events", params={"connection": "IB_ACME_ADT", "kind": "idle_timeout"})
    assert r.status_code == 200
    assert "No events." in r.text  # the filter ran; this store has no events


@pytest.mark.parametrize(
    ("field", "value", "refusal"),
    [("channel_id", BAD_NAME, NAME_REFUSAL), ("status", "ADT^A01", STATUS_REFUSAL)],
)
async def test_content_search_form_refuses_a_filter_the_json_route_refuses(
    admin: httpx.AsyncClient, field: str, value: str, refusal: str
) -> None:
    """The content-search GET form, 400 + its own banner. Its POST arm already applied these four
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
    """422 on the path segment, before the handler runs. Only a hand-built URL gets here: the
    console renders these names into form actions out of the live registry."""
    r = await admin.post(f"/ui/connections/{BAD_NAME}/{action}", headers=SFS)
    assert r.status_code == 422


@pytest.mark.parametrize("action", ["start", "stop", "restart"])
async def test_per_name_control_reaches_the_handler_for_a_valid_name(
    admin: httpx.AsyncClient, action: str
) -> None:
    """Positive control: a well-formed name passes the rule and reaches the control handler, which
    404s a connection this engine does not have. NOT 422 is the whole assertion -- a gate broken to
    refuse every name would answer 422 here too."""
    r = await admin.post(f"/ui/connections/IB_NOT_REGISTERED/{action}", headers=SFS)
    assert r.status_code != 422


async def test_purge_confirm_refuses_a_bad_destination_name(admin: httpx.AsyncClient) -> None:
    """422 on the repeated ``dest`` query value, which the console renders from live outbound names."""
    r = await admin.get("/ui/connections/purge-confirm", params={"dest": BAD_NAME})
    assert r.status_code == 422
    ok = await admin.get("/ui/connections/purge-confirm", params={"dest": "OB_ACME_ADT"})
    assert ok.status_code == 200  # positive control, same request shape


async def test_bulk_control_refuses_one_name_without_aborting_the_batch(
    admin: httpx.AsyncClient,
) -> None:
    """The capture-and-continue half. ``ui_bulk_control`` reads its names out of the POST BODY, so
    there is no parameter to annotate and a raise would fail the whole operation over one forged
    selection. The bad row becomes an OUTCOME, and the good row is still processed."""
    from messagefoundry_webconsole.pages.connections import _b64url

    def sel(name: str) -> str:
        # The console's own row-key encoding, so the selections decode exactly as a browser's would
        # and the refusal under test is the NAME rule rather than a malformed key.
        return f"source|{_b64url(name)}|{_b64url('')}"

    body = {"action": "start", "sel": [sel(BAD_NAME), sel("IB_NOT_REGISTERED")]}
    r = await admin.post("/ui/connections/bulk-control", data=body, headers=SFS)
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
        headers=SFS,
    )
    assert r.status_code == 200
    assert "not applied: not a valid connection name" in r.text
    assert BAD_NAME not in r.text
    assert "2 destination(s) processed" in r.text
