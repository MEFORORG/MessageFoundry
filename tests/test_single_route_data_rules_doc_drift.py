# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1151 -- the single-route data rules, executed and documented.

``docs/SECURITY.md`` carries a blockquote headed *Single-route data rules*. It states at least five
data rules that each sit on one route, or one family of routes, and that the route rows themselves
only point to. This file keeps that blockquote true in the same two halves as
``tests/test_monitoring_scope_doc_drift.py``, on the same seeded estate (inbounds ``IB_A`` and
``IB_B``, shared outbound ``OB_X``):

* one measurement per rule EXECUTES the route against a channel-scoped operator, with an
  all-channels operator in the same run as the positive control;
* :func:`test_security_doc_states_each_single_route_rule` reads the blockquote and requires each
  rule's routes and key facts in that rule's own bullet, every bullet to belong to a rule, and each
  route's row in the route map to point at the blockquote.

``_RULES`` is the one list both halves read. So a bullet cannot name a route that no measurement
executes, and a measured rule cannot drop out of the doc without a red.

WHAT THIS DOES NOT DO. It is not a census of the data rules the code enforces: a rule nobody has
documented is invisible to it. A bullet's facts are checked by presence and by a short list of
forbidden contradictions, not parsed, and a measurement covers the facts it names, not every clause
of the bullet. The console paragraph of the blockquote is read from the code and not executed.
"""

from __future__ import annotations

import functools
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import NamedTuple

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from tests._doc_blockquote import blockquote_lines, plant_in_blockquote, route_tokens, unwrap

# The shared fixture and helpers, imported rather than copied, as
# tests/test_route_channel_scope_classification.py does.
from tests.test_monitoring_scope_doc_drift import (  # noqa: F401
    _login,
    _operator,
    engine,
)
from tests.test_route_channel_scope_classification import ROUTES, SCOPED

_DOC = Path(__file__).resolve().parent.parent / "docs" / "SECURITY.md"

#: The blockquote's bold open. Pinned to the name, not to the punctuation after it.
_MARKER = "**Single-route data rules"

#: What every route row of a rule must carry, so a reader of the route map finds the rule.
_ROW_POINTER = "*Single-route data rules*"


# =====================================================================================================
# The measurement -- executed against a live app, scoped caller vs all-channels positive control
# =====================================================================================================


@dataclass
class _Callers:
    """A channel-scoped operator (``IB_A`` only) and an all-channels operator, both logged in."""

    engine: Engine
    c: httpx.AsyncClient
    scoped: dict[str, str]
    wide: dict[str, str]
    monkeypatch: pytest.MonkeyPatch

    async def denials(self) -> int:
        rows = await self.engine.store.list_audit(
            action="auth.channel_denied", actor="scoped", limit=500
        )
        return len(rows)


async def _measure_layered_search_owner(k: _Callers) -> None:
    async def preset(headers: dict[str, str]) -> str:
        r = await k.c.post(
            "/search/presets", json={"name": "p", "criteria": {"content": "MSG1"}}, headers=headers
        )
        assert r.status_code == 200, r.text
        return str(r.json()["id"])

    mine, theirs = await preset(k.scoped), await preset(k.wide)
    own = await k.c.get("/search/layered", params={"presets": mine}, headers=k.scoped)
    # The owner's run is narrowed to its channel scope: one of the two seeded messages...
    assert own.status_code == 200 and own.json()["matched"] == 1, own.text
    # ...where the same criteria in the wide caller's own preset match both.
    wide = await k.c.get("/search/layered", params={"presets": theirs}, headers=k.wide)
    assert wide.status_code == 200 and wide.json()["matched"] == 2, wide.text
    # Another user's preset answers 404, and so does an id that exists nowhere.
    for pid in (mine, "nope"):
        r = await k.c.get("/search/layered", params={"presets": pid}, headers=k.wide)
        assert r.status_code == 404, (pid, r.text)


async def _measure_statistics_reset(k: _Callers) -> None:
    before = await k.denials()
    everything = await k.c.post("/statistics/reset", json={"all": True}, headers=k.scoped)
    assert everything.status_code == 403, everything.text
    in_scope = {"role": "source", "channel_id": "IB_A"}
    mixed = await k.c.post(
        "/statistics/reset",
        json={"targets": [in_scope, {"role": "source", "channel_id": "IB_B"}]},
        headers=k.scoped,
    )
    assert mixed.status_code == 403, mixed.text
    assert await k.denials() == before + 2
    # The refused batch reset nothing, not even its in-scope target. The baselines are what a reset
    # moves, so they are read directly rather than inferred from the audit trail.
    eng = k.engine
    assert eng._inbound_stat_offsets == {} and eng._outbound_stat_offsets == {}
    edge = {"role": "destination", "channel_id": "IB_A", "destination": "OB_X"}
    for target in (in_scope, edge):
        r = await k.c.post("/statistics/reset", json={"targets": [target]}, headers=k.scoped)
        assert r.status_code == 200 and r.json()["reset"] == 1, (target, r.text)
    # The edge reset moved IB_A's edge into OB_X and no other inbound's edge into it.
    assert set(eng._inbound_stat_offsets) == {"IB_A"}
    assert set(eng._outbound_stat_offsets) == {("IB_A", "OB_X")}
    # Control: the all-channels caller may reset everything.
    wide = await k.c.post("/statistics/reset", json={"all": True}, headers=k.wide)
    assert wide.status_code == 200, wide.text


async def _measure_status_per_field(k: _Callers) -> None:
    rr = k.engine.registry_runner
    assert rr is not None
    # Both inbounds report a start failure. This stands in for ADR 0031's bind failure, which needs
    # a started engine; the rule under test is the narrowing in the handler, not the detection.
    k.monkeypatch.setattr(rr, "inbound_failed", lambda name: "bind failed")
    scoped_body = (await k.c.get("/status", headers=k.scoped)).json()
    wide_body = (await k.c.get("/status", headers=k.wide)).json()
    scoped, wide = scoped_body["engine"], wide_body["engine"]
    assert sorted(wide["channels_failed_names"]) == ["IB_A", "IB_B"]
    assert scoped["channels_failed_names"] == ["IB_A"]
    for field in ("channels_failed", "channels_total", "outbox_by_status"):
        assert scoped[field] == wide[field], f"{field} is estate-wide"
    assert scoped["channels_failed"] == 2
    # messages_per_second is a live rate and could tick between the two reads; the counts cannot.
    for field in ("messages_total", "connections_total", "connections_running"):
        assert scoped_body["kpis"][field] == wide_body["kpis"][field], f"kpis.{field}"
    for field in ("messages", "events"):
        assert scoped_body["db"][field] == wide_body["db"][field], f"db.{field}"
    assert wide_body["db"]["messages"] == 2


async def _measure_alert_writes(k: _Callers) -> None:
    # The shared fixture holds one open alert per connection.
    ids = {
        a.connection: a.id
        for a in await k.engine.store.list_active_alert_instances(allowed_channels=None)
    }
    writes: tuple[tuple[str, dict[str, float] | None], ...] = (
        ("ack", None),
        ("suspend", {"minutes": 5.0}),
        ("resume", None),
        ("resolve", None),
    )
    store = k.engine.store

    async def states() -> list[object]:
        return [await store.get_alert_instance(i, allowed_channels=None) for i in ids.values()]

    async def audit_rows() -> list[str]:
        # The paced gate writes auth.permission_granted at admission, before the handler runs; the
        # doc says so. Every OTHER action is the handler's, and the refusal must write none.
        rows = await store.list_audit(limit=10_000)
        return [r["action"] for r in rows if r["action"] != "auth.permission_granted"]

    for verb, body in writes:
        audited, before = await audit_rows(), await states()
        # IB_B is out of scope; OB_X is the shared outbound IB_A feeds, and is out of scope too.
        for alert_id in (ids["IB_B"], ids["OB_X"], 999_999):
            r = await k.c.post(f"/alerts/{alert_id}/{verb}", json=body, headers=k.scoped)
            assert r.status_code == 404, (verb, alert_id, r.text)
        # Refused before any state change, and with no audit row of ANY action.
        assert await states() == before, verb
        assert await audit_rows() == audited, verb
        own = await k.c.post(f"/alerts/{ids['IB_A']}/{verb}", json=body, headers=k.scoped)
        assert own.status_code == 200, (verb, own.text)
        # Control: the all-channels caller reaches the alert the scoped caller could not.
        wide = await k.c.post(f"/alerts/{ids['IB_B']}/{verb}", json=body, headers=k.wide)
        assert wide.status_code == 200, (verb, wide.text)


async def _measure_events_connection_filter(k: _Callers) -> None:
    before = await k.denials()
    out = await k.c.get("/events", params={"connection": "IB_B"}, headers=k.scoped)
    assert out.status_code == 403, out.text
    assert await k.denials() == before + 1
    own = await k.c.get("/events", params={"connection": "IB_A"}, headers=k.scoped)
    assert own.status_code == 200 and {e["connection"] for e in own.json()["events"]} == {"IB_A"}
    wide = await k.c.get("/events", params={"connection": "IB_B"}, headers=k.wide)
    assert wide.status_code == 200 and {e["connection"] for e in wide.json()["events"]} == {"IB_B"}


class _Rule(NamedTuple):
    #: The routes its bullet must name, written as the doc backticks them, compared as exact tokens.
    routes: tuple[str, ...]
    #: The facts its bullet must state: plain substrings of the unwrapped bullet.
    facts: tuple[str, ...]
    measure: Callable[[_Callers], Awaitable[None]]
    #: What its bullet must NOT say. A presence check alone passes "answers 403 (it used to answer
    #: 404)", so the status code a bullet must not give is named here.
    forbidden: tuple[str, ...] = ()


_RULES: dict[str, _Rule] = {
    "layered-search-owner": _Rule(
        ("GET /search/layered",),
        ("`user_id`", "404", "channel scope"),
        _measure_layered_search_owner,
        forbidden=("403",),
    ),
    "statistics-reset": _Rule(
        ("POST /statistics/reset",),
        (
            "`all`",
            "403",
            "`channel_id`",
            "nothing resets",
            "only that edge",
            "`auth.channel_denied`",
        ),
        _measure_statistics_reset,
        forbidden=("404",),
    ),
    "status-per-field": _Rule(
        ("GET /status",),
        (
            "`channels_failed_names`",
            "`channels_failed`",
            "`outbox_by_status`",
            "`kpis`",
            "are not narrowed",
        ),
        _measure_status_per_field,
        forbidden=("counts are narrowed",),
    ),
    "alert-writes": _Rule(
        (
            "POST /alerts/{alert_id}/ack",
            "POST /alerts/{alert_id}/resolve",
            "POST /alerts/{alert_id}/suspend",
            "POST /alerts/{alert_id}/resume",
        ),
        ("404", "shared outbound", "no audit row", "`auth.permission_granted`"),
        _measure_alert_writes,
        forbidden=("403",),
    ),
    "events-connection-filter": _Rule(
        ("GET /events",),
        ("`connection=`", "403", "`auth.channel_denied`"),
        _measure_events_connection_filter,
        forbidden=("404",),
    ),
}


@pytest.mark.parametrize("rule", sorted(_RULES))
async def test_single_route_rule_is_measured_against_a_live_app(
    rule: str,
    engine: Engine,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Pacing off: several measurements send a run of paced writes as one actor.
    service = AuthService(
        engine.store,
        AuthSettings(
            require_mfa=False,
            admin_write_min_interval_seconds=0,
            admin_write_rate_limit_enabled=False,
        ),
    )
    await service.initialize()
    scoped_id = await _operator(service, "scoped")
    await service.set_channel_scope(scoped_id, ["IB_A"], actor="admin")
    # Deny-by-default (BACKLOG #1152): the control is granted the estate rather than left unset.
    wide_id = await _operator(service, "allchannels")
    await service.set_channel_scope(wide_id, [ALL_CHANNELS], actor="admin")
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        callers = _Callers(
            engine, c, await _login(c, "scoped"), await _login(c, "allchannels"), monkeypatch
        )
        await _RULES[rule].measure(callers)


def test_every_rule_route_is_classified_scoped() -> None:
    """The channel-scope classification table must agree that each route here is scoped."""
    for rule in _RULES.values():
        for route in rule.routes:
            assert ROUTES[route][0] == SCOPED, f"{route} carries a data rule but is not SCOPED"


# =====================================================================================================
# The doc binding -- the same rules, read out of docs/SECURITY.md
# =====================================================================================================


@functools.cache
def _doc_text() -> str:
    return _DOC.read_text(encoding="utf-8")


def _bullet_spans(lines: list[str]) -> list[tuple[int, int]]:
    """``(start, end)`` line spans of each ``- `` bullet; a continuation line is indented 3."""
    spans: list[tuple[int, int]] = []
    for i, line in enumerate(lines):
        if line[1:].strip().startswith("- "):
            spans.append((i, i + 1))
        elif spans and spans[-1][1] == i and line.startswith(">   "):
            spans[-1] = (spans[-1][0], i + 1)
    return spans


def _unwrap_bullet(lines: list[str]) -> str:
    """The bullet as one string, without its ``- `` lead."""
    return unwrap(lines).removeprefix("- ")


def _problems(text: str) -> list[str]:
    problems: list[str] = []
    lines = text.splitlines()
    block = blockquote_lines(text, _MARKER)
    bullets = [_unwrap_bullet(block[a:b]) for a, b in _bullet_spans(block)]
    claimed = [route_tokens(b) for b in bullets]
    for i, tokens in enumerate(claimed):
        # Every route a bullet names must belong to the ONE rule that measures it, or an extra,
        # unexecuted route could ride along inside a measured bullet.
        if not tokens or not any(tokens <= set(rule.routes) for rule in _RULES.values()):
            problems.append(
                f"bullet {i + 1} names a route no measurement executes: {sorted(tokens)}"
            )
    for name, rule in _RULES.items():
        home = [b for b, tokens in zip(bullets, claimed, strict=True) if tokens & set(rule.routes)]
        if len(home) != 1:
            problems.append(f"{name}: expected one bullet naming {rule.routes}, found {len(home)}")
            continue
        bullet, tokens = home[0], route_tokens(home[0])
        for route in rule.routes:
            if route not in tokens:
                problems.append(f"{name}: its bullet omits {route}")
            method, path = route.split(" ", 1)
            prefix = f"| `{method}` | `{path}` |"
            row = next((line for line in lines if line.startswith(prefix)), "")
            if _ROW_POINTER not in row:
                problems.append(f"{name}: the route-map row for {route} does not point here")
        for fact in rule.facts:
            if fact not in bullet:
                problems.append(f"{name}: its bullet no longer states {fact!r}")
        for wrong in rule.forbidden:
            if wrong in bullet:
                problems.append(f"{name}: its bullet says {wrong!r}, which the code does not do")
    return problems


def test_security_doc_states_each_single_route_rule() -> None:
    assert _problems(_doc_text()) == []


@pytest.mark.parametrize("route", sorted(r for rule in _RULES.values() for r in rule.routes))
def test_guard_detects_a_planted_route_omission(route: str) -> None:
    planted = plant_in_blockquote(_doc_text(), _MARKER, f"`{route}`", "`GET /nowhere`")
    assert _problems(planted), f"deleting {route} from the blockquote did not red the guard"


def _rewrite_bullet(rule: str, edit: Callable[[str], str]) -> str:
    """The doc with ``rule``'s bullet re-emitted as one line after ``edit``, so a fact split across
    a wrap is planted too."""
    text = _doc_text()
    block = blockquote_lines(text, _MARKER)
    start, end = next(
        (a, b) for a, b in _bullet_spans(block) if route_tokens(block[a]) & set(_RULES[rule].routes)
    )
    bullet = _unwrap_bullet(block[start:end])
    planted = text.replace("\n".join(block[start:end]), "> - " + edit(bullet), 1)
    assert planted != text, f"the edit did not change the {rule} bullet"
    return planted


@pytest.mark.parametrize(
    ("rule", "fact"), sorted((name, f) for name, rule in _RULES.items() for f in rule.facts)
)
def test_guard_detects_a_planted_fact_deletion(rule: str, fact: str) -> None:
    # Every occurrence: the reset bullet says 403 twice, and planting one would leave the other.
    planted = _rewrite_bullet(rule, lambda b: b.replace(fact, "REDACTED-FACT"))
    assert any(p.startswith(f"{rule}:") for p in _problems(planted)), (
        f"deleting {fact!r} did not red {rule}"
    )


@pytest.mark.parametrize(
    ("rule", "wrong"), sorted((name, w) for name, rule in _RULES.items() for w in rule.forbidden)
)
def test_guard_detects_a_planted_contradiction(rule: str, wrong: str) -> None:
    """A contradiction that keeps the true token, such as the alert writes' 404 turned into the 403
    the other refusals give, "(it used to answer 404)" and all."""
    planted = _rewrite_bullet(rule, lambda b: f"{b} It answers {wrong} instead.")
    assert any(p.startswith(f"{rule}:") for p in _problems(planted)), (
        f"adding {wrong!r} did not red {rule}"
    )


def test_guard_detects_an_extra_route_in_a_measured_bullet() -> None:
    planted = _rewrite_bullet(
        "events-connection-filter", lambda b: f"{b} So does `GET /connections/{{name}}/events`."
    )
    assert any("no measurement executes" in p for p in _problems(planted))


def test_guard_detects_an_unmeasured_bullet() -> None:
    """The other direction: a bullet no rule claims is a documented rule nothing executes."""
    anchor = "> - `GET /status`"
    planted = _doc_text().replace(anchor, "> - `GET /nowhere` is a new rule.\n" + anchor, 1)
    assert planted != _doc_text()
    assert any("no measurement executes" in p for p in _problems(planted))


def test_guard_detects_a_dropped_row_pointer() -> None:
    text = _doc_text()
    row = next(line for line in text.splitlines() if line.startswith("| `GET` | `/status` |"))
    assert _ROW_POINTER in row
    planted = text.replace(row, row.replace(_ROW_POINTER, "nothing here"), 1)
    assert any("does not point here" in p for p in _problems(planted))
