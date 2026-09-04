# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ASVS 14.2.2 -- ``Cache-Control: no-store`` on every response that carries classified data, and a
drift guard that blocks the next uncovered one.

The engine writes ``Cache-Control`` in exactly one place, the ``_security_headers`` middleware. It
used to write it BY URL PREFIX ONLY, which is why three PHI reads once shipped header-free: ``GET
/search/layered``, ``GET /logs/tail`` and ``GET /uploads/{file_id}/messages`` each arrived as a NEW
member of a route family whose prefix was not in the list.

**Why this module was rewritten (BACKLOG #1185).** The guard that closed those three selected a route
as sensitive **by its permission gate** -- ``require_phi_read``, an explicit PHI-hop charge, or a
GET/HEAD ``require_step_up``. That predicate is structurally unable to see a route returning a
classified column under a DIFFERENT permission, and three such routes were shipping with no cache
directive at all while this module was green: ``GET /events`` and ``GET /connections/{name}/events``
return ``connection_event.reason`` under ``monitoring:read``, and ``GET /alerts/active`` returns
``alert_instance.reason`` under ``monitoring:diagnose``. Both columns are rated **PL-2** in
``docs/PHI.md`` section 2.

Adding those paths and leaving the predicate gate-shaped would have been a green that measured
nothing: the NEXT classified monitoring route would ship uncovered and this file would still read as
coverage. A control whose blindness has not been tested is not evidence.

**The predicate is now CLASSIFICATION-shaped, and it does not consult the gate.** A route is selected
when its response model, walked recursively, projects a store column ``docs/PHI.md`` rates PL-1, PL-2
or PL-3. The rating is READ OUT OF ``docs/PHI.md`` rather than restated here, so this guard cannot
disagree with the classification document it measures against. The field-to-column binding,
:data:`_RESPONSE_FIELD_COLUMN`, is the one reviewed part, and
:func:`test_every_colliding_response_field_is_bound` fails on any field it does not resolve. That is
the deny-by-default hinge: a new response field whose name collides with a classified column reds this
module until somebody classifies it.

The old gate-shaped arm is KEPT as a second disjunct. It costs nothing, and it still reaches a PHI
read that no model walk can see -- ``GET /messages/{message_id}/attachments/{attachment_id}`` streams
raw bytes and declares no ``response_model`` at all.

**Two rulings this module deliberately does NOT make**, both recorded as open questions on BACKLOG
#1185. First, the route and model docstrings say "metadata only, no PHI" while ``docs/PHI.md`` rates
their ``reason`` column PL-2; one of the two is wrong and the ASVS cell rests on which. This file is
built as though PL-2 is correct, because PL-2 is the shipped classification. Second, whether
"sensitive data" in the 14.2.2 verb tracks the PHI PERMISSION or the PHI CLASSIFICATION is unsettled.
This guard makes the classification-shaped reading buildable and asserts nothing about the other.
"""

from __future__ import annotations

import functools
import inspect
import re
import typing
from collections.abc import AsyncIterator

import httpx
import pytest
from fastapi import FastAPI
from fastapi.routing import APIRoute
from pydantic import BaseModel

from messagefoundry.api import create_app
from messagefoundry.api.app import _NO_STORE_PREFIXES, _NO_STORE_ROUTE_PATHS
from messagefoundry.api.models import ConnectionEventInfo
from messagefoundry.pipeline import Engine

# Which section of docs/PHI.md the at-rest inventory is, what a row of it looks like, and which cell
# carries the protection level are all DEFINED once -- in the inventory guard next door. A second copy
# of that parser is the silently-divergent second definition CLAUDE.md section 11 forbids, so this
# imports it. `_section_2_levels` keys a row by its FIRST backticked token, which is not enough here
# (a two-column row like `response.detail`, `response.resp_headers` must classify both), so
# `_classified_columns` re-keys the same rows -- and `test_the_two_phi_md_parsers_agree` asserts the
# two never disagree about a level.
from tests.test_phi_at_rest_inventory import _section, _section_2_levels, _table_rows

#: Qualname prefixes of the auth-dependency closures ``Depends(require_*(...))`` installs on a route.
_PHI_READ_DEP = "require_phi_read."
_STEP_UP_DEP = "require_step_up."
#: The explicit PHI-read declaration a step-up bulk-PHI handler makes in its own body.
_HOP_CALL = "enforce_phi_read_hop("

#: The protection levels that make a response body worth withholding from an intermediary's cache.
#: PL-4 (operational metadata) and PL-5 (engine-unreachable substrate) are deliberately out.
_SENSITIVE_LEVELS = frozenset({"PL-1", "PL-2", "PL-3"})

#: A ``table.column`` token as docs/PHI.md section 2 writes one in a row's first cell.
_COLUMN_TOKEN = re.compile(r"`([a-z_]+\.[a-z_]+)`")


# --- the classification, read out of docs/PHI.md --------------------------------------------------


@functools.cache
def _classified_columns() -> dict[str, str]:
    """``{"connection_event.reason": "PL-2", ...}`` straight out of ``docs/PHI.md`` section 2.

    Every ``table.column`` token in a row's first cell takes that row's protection level. The level is
    picked by the SAME rule ``_section_2_levels`` uses -- the first cell that starts with ``**PL-`` --
    so the two parsers cannot drift into disagreeing about a row. Cached: the doc is 163 KB, and a
    full route walk would otherwise re-read and re-parse it once per route.
    """
    levels: dict[str, str] = {}
    for line in _table_rows(_section(2)).splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        level = next((c for c in cells if c.startswith("**PL-")), None)
        if len(cells) < 5 or level is None:
            continue
        for column in _COLUMN_TOKEN.findall(cells[0]):
            levels[column] = level.strip("*")
    return levels


#: Which store column each response-model field PROJECTS, or ``None`` when it projects none.
#:
#: ``None`` is a statement about PROVENANCE, not about sensitivity. It says the value is composed in
#: the route body from live engine state, so no section 2 row rates it -- it does NOT assert the value
#: is harmless. Two entries below are live free-text diagnostics shaped very like their persisted
#: twin, and they are recorded as an open question on BACKLOG #1185 rather than ruled here.
#:
#: The register exists because a bare COLUMN NAME is ambiguous across tables: ``detail`` is PL-2 as
#: ``message_events.detail`` and PL-4 as ``audit_log.detail``. Matching on the name alone selected 34
#: uncovered routes, almost all of them ``SimpleMessage.detail`` -- a literal operation-result string.
#:
#: A SECOND, coarser judgement over some of these same models lives in
#: ``tests/test_security_doc_drift.py`` (``_NO_PHI_RESPONSE_MODELS`` and
#: ``_MAPPED_MODEL_NON_PHI_FIELDS``, model-level rather than field-to-column). Update both when a
#: model's PHI posture changes.
_RESPONSE_FIELD_COLUMN: dict[tuple[str, str], str | None] = {
    # --- projections of a classified store column ---------------------------------------------
    ("MessageSummary", "summary"): "messages.summary",
    ("MessageSummary", "error"): "messages.error",
    ("MessageSummary", "metadata"): "messages.metadata",
    ("MessageDetail", "summary"): "messages.summary",
    ("MessageDetail", "error"): "messages.error",
    ("MessageDetail", "metadata"): "messages.metadata",
    ("MessageDetail", "raw"): "messages.raw",
    ("DeadLetterRow", "summary"): "messages.summary",
    ("DeadLetterRow", "last_error"): "queue.last_error",
    ("OutboxInfo", "last_error"): "queue.last_error",
    ("EventInfo", "detail"): "message_events.detail",
    ("CapturedResponseInfo", "body"): "response.body",
    ("CapturedResponseInfo", "detail"): "response.detail",
    ("OutboundPayloadInfo", "payload"): "queue.payload",
    # The two the gate-shaped predicate could never see: PL-2 free text behind a monitoring:*
    # permission rather than a PHI one. This is the whole subject of BACKLOG #1185.
    ("ConnectionEventInfo", "reason"): "connection_event.reason",
    ("AlertInstanceInfo", "reason"): "alert_instance.reason",
    # --- projections of a column section 2 rates PL-4 (operational metadata, not withheld) -----
    # audit_log.detail is JSON metadata about an action -- exposed ids and counts, never a body.
    ("AuditEntry", "detail"): "audit_log.detail",
    ("SecurityEventInfo", "detail"): "audit_log.detail",
    # --- composed in the route body; no store column to rate -----------------------------------
    ("SimpleMessage", "detail"): None,  # a literal operation-result string
    ("IntegrityResult", "detail"): None,  # the backend's own integrity-check output
    ("PendingApprovalResponse", "detail"): None,  # why the action is held for a second approver
    ("AlertTestEmailResult", "detail"): None,  # a safe_exc-scrubbed SMTP send failure
    ("ConnectionTestResult", "detail"): None,  # a reachability-probe outcome
    ("AiPolicy", "reason"): None,  # why the AI policy clamped, derived from config
    ("ConnectionMetadata", "metadata"): None,  # the operator's own connections.toml label table
    # OPEN QUESTION, recorded on BACKLOG #1185 and deliberately NOT ruled here. These two carry a
    # connector's start-failure string from the RegistryRunner (ADR 0031) -- live engine state, so no
    # section 2 row rates them. Their persisted twin, connection_event.reason, IS rated PL-2. Whether
    # the live string deserves the same rating is a classification ruling for the owner.
    ("ConnectionRow", "error"): None,
    ("ConnectionMetadata", "error"): None,
}


# --- route walking --------------------------------------------------------------------------------


def _response_models(annotation: object) -> list[type[BaseModel]]:
    """Every pydantic model reachable from a route's ``response_model``, through lists and unions."""
    found: list[type[BaseModel]] = []
    seen: set[type] = set()
    stack: list[object] = [annotation]
    while stack:
        cur = stack.pop()
        if isinstance(cur, type) and issubclass(cur, BaseModel):
            if cur in seen:
                continue
            seen.add(cur)
            found.append(cur)
            stack.extend(f.annotation for f in cur.model_fields.values())
        elif typing.get_origin(cur) is not None:
            stack.extend(typing.get_args(cur))
    return found


def _colliding_fields(app: FastAPI) -> set[tuple[str, str]]:
    """Every ``(model, field)`` in the app whose field NAME is also a classified column's name.

    Name collision is the cheap, over-inclusive trigger; :data:`_RESPONSE_FIELD_COLUMN` is what
    resolves each one. Over-inclusive is the right direction here -- an unresolved collision fails.
    """
    names = {
        c.split(".")[1] for c, lvl in _classified_columns().items() if lvl in _SENSITIVE_LEVELS
    }
    found: set[tuple[str, str]] = set()
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        for model in _response_models(route.response_model):
            found |= {(model.__name__, f) for f in model.model_fields if f in names}
    return found


def _classified_columns_of(route: APIRoute) -> dict[str, str]:
    """``{column: level}`` for every PL-1/PL-2/PL-3 column this route's response projects."""
    levels = _classified_columns()
    carried: dict[str, str] = {}
    for model in _response_models(route.response_model):
        for field in model.model_fields:
            column = _RESPONSE_FIELD_COLUMN.get((model.__name__, field))
            if column is not None and levels.get(column, "") in _SENSITIVE_LEVELS:
                carried[column] = levels[column]
    return carried


def _dependency_qualnames(route: APIRoute) -> set[str]:
    """Every dependency callable on the route, recursively (a gate closure can nest)."""
    found: set[str] = set()
    pending = [route.dependant]
    while pending:
        for sub in pending.pop().dependencies:
            call = getattr(sub, "call", None)
            if call is not None:
                found.add(getattr(call, "__qualname__", ""))
            pending.append(sub)
    return found


def _handler_charges_phi_hop(route: APIRoute) -> bool:
    try:
        return _HOP_CALL in inspect.getsource(route.endpoint)
    except (
        OSError,
        TypeError,
    ):  # source unavailable (zipped install) -- fall back to the gate arms
        return False


def _is_phi_read_by_gate(route: APIRoute) -> bool:
    """The ORIGINAL, permission-gate-shaped predicate, kept as one disjunct and as the blindness
    control. PHI-read gate, or an explicit hop charge, or a GET/HEAD step-up.

    The GET/HEAD scoping on the step-up arm is load-bearing: anti-caching is a property of cacheable
    reads, and an unscoped step-up-over-PHI predicate lands red on ``POST /connections/{name}/purge``
    -- a step-up route returning cancellation counts, no PHI, from outside every covered path.
    """
    quals = _dependency_qualnames(route)
    if any(q.startswith(_PHI_READ_DEP) for q in quals) or _handler_charges_phi_hop(route):
        return True
    cacheable = bool({"GET", "HEAD"} & (route.methods or set()))
    return cacheable and any(q.startswith(_STEP_UP_DEP) for q in quals)


def _is_sensitive(route: APIRoute) -> bool:
    """The guard's predicate: what the response CARRIES, or failing that, what gates it."""
    return bool(_classified_columns_of(route)) or _is_phi_read_by_gate(route)


def _sensitive_routes(app: FastAPI) -> list[APIRoute]:
    return [r for r in app.routes if isinstance(r, APIRoute) and _is_sensitive(r)]


def _is_covered(route: APIRoute) -> bool:
    return route.path.startswith(_NO_STORE_PREFIXES) or route.path in _NO_STORE_ROUTE_PATHS


def _concrete(path: str) -> str:
    """A drivable URL for a route template. ``1`` parses as both an int and a str path param."""
    return re.sub(r"\{[^}]+\}", "1", path)


#: The PHI reads the gate-shaped arm must keep selecting. Pinned literally so a refactor that makes
#: that arm return False for everything (a green, vacuous guard) fails here instead of passing.
_EXPECTED_PHI_READS = frozenset(
    {
        "/dead-letters",
        "/messages",
        "/messages/search",
        "/messages/export",
        "/messages/{message_id}",
        "/messages/{message_id}/attachments/{attachment_id}",
        "/messages/{message_id}/outbound",
        "/messages/{message_id}/responses",
        "/search/layered",
        "/logs/tail",
        "/uploads/{file_id}/messages",
    }
)

#: The routes only the CLASSIFICATION arm can see -- every one of them gated on a monitoring
#: permission. Pinned for the same reason: an arm that selects nothing is not a guard.
#:
#: Deliberately a SEPARATE literal from ``app._NO_STORE_ROUTE_PATHS`` rather than a reference to it,
#: even though the two agree today. Asserting against the app's own constant would let a change that
#: DELETES a path from it stay green -- the expectation would shrink with the thing it checks.
_EXPECTED_CLASSIFIED_ONLY = frozenset(
    {
        "/events",
        "/connections/{name}/events",
        "/alerts/active",
        "/alerts/{alert_id}/ack",
        "/alerts/{alert_id}/resolve",
        "/alerts/{alert_id}/suspend",
        "/alerts/{alert_id}/resume",
    }
)

#: Every PHI response that emitted no ``Cache-Control`` at all before the prefix set closed them.
_PREVIOUSLY_UNCOVERED = ("/search/layered", "/logs/tail", "/uploads/f1/messages")


# One engine and one app for the whole module. Every test here READS the app (walks its routes, drives
# requests against an empty store); none mutates engine state, and the one test that mutates an app
# builds its own. Function scope cost about 2s of Engine.create per test, which dominated this
# module's runtime once the test count grew.
@pytest.fixture(scope="module")
async def engine(tmp_path_factory: pytest.TempPathFactory) -> AsyncIterator[Engine]:
    db = tmp_path_factory.mktemp("no_store") / "no_store.db"
    eng = await Engine.create(db, poll_interval=0.02)
    yield eng
    await eng.stop()


@pytest.fixture(scope="module")
def app(engine: Engine) -> FastAPI:
    return create_app(engine, allow_no_auth=True, serve_ui=False)


@pytest.fixture(scope="module")
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        yield c


# --- the classification is read, not restated ------------------------------------------------------


def test_the_phi_md_classification_parses() -> None:
    """Positive control on the instrument. A parser that silently returned nothing would make every
    classification assertion below vacuously true, which is the failure this whole module is about."""
    levels = _classified_columns()
    assert levels.get("messages.raw") == "PL-1"
    assert levels.get("connection_event.reason") == "PL-2"
    assert levels.get("alert_instance.reason") == "PL-2"
    assert levels.get("users.totp_secret") == "PL-3"
    # The ambiguity the field-to-column register exists to resolve: one bare name, two levels.
    assert levels.get("message_events.detail") == "PL-2"
    assert levels.get("audit_log.detail") == "PL-4"


def test_the_two_phi_md_parsers_agree() -> None:
    """Two readings of one table must not drift. ``_section_2_levels`` keys a row by its first
    backticked token; this module re-keys the same rows by EVERY ``table.column`` token in the cell.
    Where both produce a key the level must match -- otherwise one of them is quietly reclassifying a
    column, and whichever test reads that parser goes green with the wrong answer."""
    mine = _classified_columns()
    theirs = _section_2_levels()
    shared = sorted(set(mine) & set(theirs))
    assert shared, "the two parsers now share no keys at all -- one of them has stopped working"
    disagree = {k: (mine[k], theirs[k]) for k in shared if mine[k] != theirs[k]}
    assert disagree == {}, f"the two docs/PHI.md section 2 parsers disagree: {disagree}"


def test_every_bound_column_is_classified_in_phi_md() -> None:
    """The register cannot bind a field to a column ``docs/PHI.md`` does not rate. Without this a
    typo ("connection_events.reason") would silently classify the route as carrying nothing."""
    levels = _classified_columns()
    unknown = sorted(
        {c for c in _RESPONSE_FIELD_COLUMN.values() if c is not None and c not in levels}
    )
    assert unknown == [], f"_RESPONSE_FIELD_COLUMN names columns section 2 does not rate: {unknown}"


def test_every_colliding_response_field_is_bound(app: FastAPI) -> None:
    """THE DENY-BY-DEFAULT HINGE. Every response field whose name collides with a PL-1/2/3 column
    must be resolved by :data:`_RESPONSE_FIELD_COLUMN` -- either to the column it projects, or to
    ``None`` with a stated reason. An unresolved collision reds here, which is how the next classified
    monitoring route gets classified instead of shipping uncovered."""
    collisions = _colliding_fields(app)
    unbound = sorted(collisions - set(_RESPONSE_FIELD_COLUMN))
    assert unbound == [], (
        "response field(s) whose name matches a PL-1/2/3 column in docs/PHI.md are not classified: "
        f"{unbound}. Add each to _RESPONSE_FIELD_COLUMN -- the store column it projects, or None "
        "with the reason it projects none."
    )
    stale = sorted(set(_RESPONSE_FIELD_COLUMN) - collisions)
    assert stale == [], f"_RESPONSE_FIELD_COLUMN entries for fields that no longer exist: {stale}"


# --- the blindness this module was rewritten to fix -------------------------------------------------


def test_the_gate_shaped_predicate_is_blind_to_the_monitoring_pl2_routes(app: FastAPI) -> None:
    """THE PROOF, on real routes rather than a fixture. For each of the three monitoring reads the
    OLD permission-gate predicate returns False while the response demonstrably projects a PL-2
    column -- so the old guard's own assertion came back empty and green while all three shipped with
    no cache directive. Selection must not depend on which permission gates the route."""
    routes = {r.path: r for r in app.routes if isinstance(r, APIRoute)}
    for path in ("/events", "/connections/{name}/events", "/alerts/active"):
        route = routes[path]
        assert not _is_phi_read_by_gate(route), f"{path} is no longer monitoring-gated; re-cut this"
        carried = _classified_columns_of(route)
        assert carried, f"{path} stopped projecting a classified column; re-cut this proof"
        assert set(carried.values()) == {"PL-2"}, carried
        assert _is_sensitive(route), f"the new predicate must see {path}"

    # And the blindness itself: the old predicate alone reports full coverage over this app.
    old_uncovered = [
        r.path
        for r in app.routes
        if isinstance(r, APIRoute) and _is_phi_read_by_gate(r) and not _is_covered(r)
    ]
    assert old_uncovered == [], (
        "the gate-shaped arm is expected to report clean -- that is the point: it reported clean "
        f"while three PL-2 routes were uncovered. Got {old_uncovered}"
    )


def test_the_classification_guard_fires_on_a_planted_uncovered_route(engine: Engine) -> None:
    """THE MUTATION CONTROL. Plant the exact case the old predicate misses -- a route returning a
    PL-2 column from outside every covered path, with no PHI gate on it at all -- and confirm the new
    predicate fires while the old one stays silent. A guard nobody has made fail is not evidence.

    Builds its own app: this test MUTATES the route table, and the module's shared app must not
    inherit a planted route.
    """
    planted_app = create_app(engine, allow_no_auth=True, serve_ui=False)

    @planted_app.get("/planted-event-feed", response_model=list[ConnectionEventInfo])
    async def _planted() -> list[ConnectionEventInfo]:  # pragma: no cover - never called
        return []

    planted = next(
        r for r in planted_app.routes if isinstance(r, APIRoute) and r.path == "/planted-event-feed"
    )
    assert not _is_phi_read_by_gate(planted), "the old predicate is supposed to MISS this"
    assert _classified_columns_of(planted) == {"connection_event.reason": "PL-2"}
    assert _is_sensitive(planted) and not _is_covered(planted)

    uncovered = [r.path for r in _sensitive_routes(planted_app) if not _is_covered(r)]
    assert uncovered == ["/planted-event-feed"], uncovered


# --- the drift guard -------------------------------------------------------------------------------


def test_every_sensitive_route_is_covered(app: FastAPI) -> None:
    """THE GUARD, in the direction that can fail: a route whose response projects a PL-1/2/3 column
    (or which is PHI-gated) and which no covered path reaches reds here."""
    uncovered = sorted(r.path for r in _sensitive_routes(app) if not _is_covered(r))
    assert uncovered == [], (
        "route(s) carrying classified data outside every no-store path -- they will be served with "
        f"no Cache-Control and may be retained by an intermediary: {uncovered}"
    )


async def test_every_sensitive_read_serves_no_store_on_the_wire(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    """The header as an intermediary sees it, not as the constant claims it. Every selected GET/HEAD
    route is driven through the real ASGI app; status-agnostic, because a directive that appears only
    on the happy path is not one a cache can rely on."""
    driven = 0
    missing: list[str] = []
    for route in _sensitive_routes(app):
        for method in sorted({"GET", "HEAD"} & (route.methods or set())):
            driven += 1
            resp = await client.request(method, _concrete(route.path))
            if resp.headers.get("cache-control") != "no-store":
                missing.append(f"{method} {route.path} -> {resp.headers.get('cache-control')!r}")
    assert driven >= len(_EXPECTED_PHI_READS), f"only {driven} request(s) driven -- selection broke"
    assert missing == [], f"selected route(s) served without no-store: {missing}"


async def test_the_classified_write_replies_are_no_store_too(
    app: FastAPI, client: httpx.AsyncClient
) -> None:
    """The four alert-mutation POSTs return the same ``AlertInstanceInfo``, PL-2 ``reason`` included.
    A POST reply is not the caching risk a GET is, so the read test above scopes itself to cacheable
    methods -- but the payload is identical and the middleware stamps it anyway, so the claim is
    measured rather than assumed. Non-GET methods only; the reads are covered above."""
    routes = {r.path: r for r in app.routes if isinstance(r, APIRoute)}
    driven = 0
    missing: list[str] = []
    for path in sorted(_NO_STORE_ROUTE_PATHS):
        for method in sorted((routes[path].methods or set()) - {"OPTIONS", "GET", "HEAD"}):
            driven += 1
            resp = await client.request(method, _concrete(path))
            if resp.headers.get("cache-control") != "no-store":
                missing.append(f"{method} {path} -> {resp.headers.get('cache-control')!r}")
    assert driven == 4, f"expected the 4 alert-mutation replies, drove {driven} -- re-cut this test"
    assert missing == [], f"_NO_STORE_ROUTE_PATHS member(s) served without no-store: {missing}"


# --- non-vacuity of both arms -----------------------------------------------------------------------


def test_the_gate_arm_still_selects_the_known_phi_reads(app: FastAPI) -> None:
    """Without this a refactor that made the gate arm return False for everything would leave the
    guard green and half-empty -- and the classification arm alone does not reach a PHI read whose
    response model this register has not learned, nor one with no response model at all."""
    selected = {r.path for r in app.routes if isinstance(r, APIRoute) and _is_phi_read_by_gate(r)}
    assert selected >= _EXPECTED_PHI_READS, f"gate arm stopped: {_EXPECTED_PHI_READS - selected}"


def test_the_classification_arm_selects_what_only_it_can_see(app: FastAPI) -> None:
    """The other half of the non-vacuity pair, and the one that matters for BACKLOG #1185: these
    seven are invisible to the gate arm, so if the classification arm goes quiet nothing else here
    would notice."""
    selected = {
        r.path
        for r in app.routes
        if isinstance(r, APIRoute) and _classified_columns_of(r) and not _is_phi_read_by_gate(r)
    }
    assert selected >= _EXPECTED_CLASSIFIED_ONLY, (
        f"classification arm stopped selecting: {_EXPECTED_CLASSIFIED_ONLY - selected}"
    )


def test_non_phi_step_up_write_is_not_selected(app: FastAPI) -> None:
    """The gate arm's binding correction, pinned. ``POST /connections/{name}/purge`` is step-up-gated
    over a MESSAGES_* permission but returns cancellation counts, not PHI, and sits outside every
    covered path -- an unscoped step-up-over-PHI predicate would red the guard on it on day one."""
    purge = [
        r for r in app.routes if isinstance(r, APIRoute) and r.path == "/connections/{name}/purge"
    ]
    assert len(purge) == 1
    assert "POST" in (purge[0].methods or set())
    assert any(q.startswith(_STEP_UP_DEP) for q in _dependency_qualnames(purge[0]))
    assert not _is_sensitive(purge[0])


# --- the served header ------------------------------------------------------------------------------


@pytest.mark.parametrize("path", _PREVIOUSLY_UNCOVERED)
async def test_previously_uncovered_phi_reads_are_no_store(
    client: httpx.AsyncClient, path: str
) -> None:
    """The three PHI responses that emitted no ``Cache-Control`` at all before the prefix set closed
    them. Asserted on the SERVED response, and status-agnostic on purpose: the middleware must stamp
    the header whatever the route body does (an unconfigured upload store 503s, a missing preset
    422s)."""
    r = await client.get(path)
    assert r.headers.get("cache-control") == "no-store"


@pytest.mark.parametrize(
    "path", ["/messages", "/dead-letters", "/search/presets", "/uploads", "/logs"]
)
async def test_no_store_families_stay_covered(client: httpx.AsyncClient, path: str) -> None:
    """One member per prefix family, so a future narrowing of ``_NO_STORE_PREFIXES`` (back to explicit
    route paths, say) is caught rather than silently shrinking the covered set."""
    r = await client.get(path)
    assert r.headers.get("cache-control") == "no-store"


async def test_no_store_is_not_blanket(client: httpx.AsyncClient) -> None:
    """The covered set is scoped, not global: non-PHI operational reads are deliberately left
    cacheable-by-default, which is what keeps the header a meaningful signal where it IS set."""
    for path in ("/health", "/status"):
        assert (await client.get(path)).headers.get("cache-control") is None
