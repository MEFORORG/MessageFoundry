# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The High Availability page and its stepdown control (ADR 0056, BACKLOG #1495).

Two halves. The page builders are pure, so the control's enable rule, the leaderless-window wording and
the per-status refusal pages are pinned without an engine. The routes then run against a real engine
whose coordinator is a stand-in, the house pattern ``tests/test_api_cluster_stepdown.py`` uses: the real
``POST /cluster/stepdown`` handler runs behind the console's own gate, so every status a page renders
here is one that handler actually raised.
"""

from __future__ import annotations

import itertools
import json
import re
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import asdict, replace
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.api.models import ClusterNode, ClusterNodeList, ClusterStatus
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings, ClusterSettings
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.cluster import (
    ClusterMember,
    NullCoordinator,
    StepdownLockTimeout,
    StepdownReleaseUnconfirmed,
    has_promotable_sibling,
    stepdown_pause_seconds,
)
from messagefoundry_webconsole import pages
from messagefoundry_webconsole.pages.cluster import _takeover_candidates

PW = "a-strong-test-passphrase"  # >=15, no app/vendor terms — satisfies the ASVS policy (WP-3)
SAME_ORIGIN = {"Sec-Fetch-Site": "same-origin"}
CONFIRM = "/ui/cluster/stepdown-confirm"
FORCE_CONFIRM = "/ui/cluster/force-stepdown-confirm"

# --- the page builders -----------------------------------------------------------------------------


def _status(
    node_id: str = "node-a", *, clustered: bool = True, is_leader: bool = True
) -> ClusterStatus:
    role = "single-node" if not clustered else ("primary" if is_leader else "standby")
    return ClusterStatus(
        node_id=node_id, clustered=clustered, is_leader=is_leader, role=role, config_version=3
    )


def _node(
    node_id: str,
    *,
    is_leader: bool = False,
    fresh: bool = True,
    promotable: bool = True,
    status: str = "active",
) -> ClusterNode:
    return ClusterNode(
        node_id=node_id,
        host="h1",
        pid=42,
        status=status,
        started_at=1_700_000_000.0,
        last_seen=1_700_000_010.0,
        is_leader=is_leader,
        promotable=promotable,
        fresh=fresh,
    )


def _nodes(
    *members: ClusterNode, leader: str | None = "node-a", lease_owner: str | None = "node-a"
) -> ClusterNodeList:
    return ClusterNodeList(
        nodes=list(members),
        leader_node_id=leader,
        lease_owner=lease_owner,
        lease_expires_at=1_700_000_030.0,
    )


def _healthy() -> ClusterNodeList:
    """node-a leads; node-b is a live promotable standby."""
    return _nodes(_node("node-a", is_leader=True), _node("node-b"))


def _offers(html: str, path: str) -> bool:
    """Whether the page carries a live form to ``path``. A disabled button carries no action at all,
    so this is the question "can the operator act", not "is the label on screen"."""
    return f'action="{path}"' in html


def _h1(html: str) -> str:
    match = re.search(r"<h1>(.*?)</h1>", html)
    assert match is not None, "the page rendered no heading"
    return match.group(1)


def test_the_leader_with_cluster_control_is_offered_both_actions() -> None:
    html = str(pages.high_availability(_status(), _healthy(), can_control=True))
    assert _offers(html, CONFIRM)
    assert _offers(html, FORCE_CONFIRM)
    assert "disabled title=" not in html
    assert "Leader: node-a." in html
    assert "enabled (active-passive)" in html
    # The live body is a fragment target, polled the way the Flow page is.
    assert 'data-fragment-url="/ui/cluster/live"' in html


@pytest.mark.parametrize(
    ("cluster", "nodes", "can_control", "reason"),
    [
        (
            _status(clustered=False),
            _nodes(_node("node-a", is_leader=True, fresh=False)),
            True,
            "Clustering is not enabled",
        ),
        (_status(), _healthy(), False, "needs the cluster:control permission"),
        (
            # This node's own flag agrees there is no leader; with the flag still set, the same
            # heartbeat reads as leadership changing hands instead (the next case).
            _status(is_leader=False),
            _nodes(_node("node-a"), _node("node-b"), leader=None),
            True,
            "No node holds live leadership",
        ),
        (_status(is_leader=False), _healthy(), True, "Leadership is changing hands"),
        (
            _status("node-b", is_leader=False),
            _healthy(),
            True,
            "open the console on the leader, node-a",
        ),
    ],
    ids=["single-node", "no-permission", "no-leader", "flag-and-heartbeat-disagree", "standby"],
)
def test_the_control_is_disabled_with_its_reason_whenever_it_cannot_act(
    cluster: ClusterStatus, nodes: ClusterNodeList, can_control: bool, reason: str
) -> None:
    html = str(pages.high_availability(cluster, nodes, can_control=can_control))
    assert not _offers(html, CONFIRM)
    assert not _offers(html, FORCE_CONFIRM)
    # Both buttons carry the reason as a tooltip, and it is also printed once for a reader who cannot
    # hover: three copies, and a count, so a page that dropped the visible line fails here.
    assert html.count("disabled title=") == 2
    assert html.count(reason) == 3, reason


def test_the_leaderless_window_reads_as_a_failover_in_progress() -> None:
    """ADR 0056's step 4, which outlives the console it was written for: right after a stepdown there
    is a real window with no live leader, and a bare "no leader" would tell the operator who clicked
    that they broke the cluster."""
    released = _nodes(_node("node-a"), _node("node-b"), leader=None, lease_owner="node-a")
    html = str(pages.high_availability(_status(is_leader=False), released, can_control=True))
    assert "Failover in progress" in html
    # The node that let go is the lease owner, and it is not offered as its own successor.
    assert "Nodes that can take it: node-b." in html


def test_a_leaderless_cluster_with_no_candidate_does_not_claim_a_failover() -> None:
    drained = _nodes(
        _node("node-a"), _node("node-b", fresh=False), leader=None, lease_owner="node-a"
    )
    html = str(pages.high_availability(_status(is_leader=False), drained, can_control=True))
    assert "Failover in progress" not in html
    assert "nothing else can take the lease" in html


def test_a_divergent_lease_owner_is_shown_as_the_source_of_truth() -> None:
    moving = _nodes(_node("node-a", is_leader=True), _node("node-b"), lease_owner="node-b")
    html = str(pages.high_availability(_status(), moving, can_control=True))
    assert "The lease names node-b." in html


def test_each_node_state_comes_from_the_engine_signals() -> None:
    nodes = _nodes(
        _node("node-a", is_leader=True),
        _node("node-b"),
        _node("node-c", promotable=False),
        _node("node-d", fresh=False),
        _node("node-e", status="left"),
    )
    html = str(pages.high_availability(_status(), nodes, can_control=True))
    for line in (
        "Leader, running the graph",
        "Standby, can take over",
        "Standby, never takes over (promotable = false)",
        "Stale: heartbeat missed",
        "Left the cluster",
    ):
        assert line in html, line
    assert "node-a (this console)" in html


def test_a_leader_with_no_successor_is_warned_before_the_engine_refuses() -> None:
    alone = _nodes(_node("node-a", is_leader=True), _node("node-b", promotable=False))
    html = str(pages.high_availability(_status(), alone, can_control=True))
    assert _offers(html, CONFIRM)  # still offered: the engine's own read decides, not this snapshot
    assert "the engine would refuse a planned stepdown" in html


def test_no_page_renders_a_vip() -> None:
    """``GET /cluster/status`` has no ``vip`` member and the engine binds no address (BACKLOG #1495,
    "What NOT to build"), so neither a VIP owner nor a promise that one moves may appear."""
    vip = re.compile(r"\bvip\b", re.IGNORECASE)
    assert vip.search("the VIP will move"), "positive control: the pattern must find a VIP"
    rendered = [
        pages.high_availability(_status(), _healthy(), can_control=True, notice="released"),
        pages.high_availability(_status(), _healthy(), can_control=True, notice="drained"),
        pages.stepdown_confirm(_status(), _healthy(), force=False),
        pages.stepdown_confirm(_status(), _healthy(), force=True),
        *(pages.stepdown_refused(s, "engine detail") for s in (400, 409, 412, 503, 500)),
    ]
    for html in rendered:
        assert not vip.search(str(html))


def test_hostile_node_identifiers_render_inert() -> None:
    evil = "<script>alert(1)</script>"
    nodes = _nodes(_node(evil, is_leader=True), _node("node-b"), leader=evil, lease_owner=evil)
    for html in (
        str(pages.high_availability(_status(evil), nodes, can_control=True)),
        str(pages.stepdown_confirm(_status(evil), nodes, force=True)),
        str(pages.stepdown_refused(503, f"node {evil} could not")),
    ):
        assert evil not in html
        assert "&lt;script&gt;" in html


def test_the_planned_confirm_names_the_successors_and_posts_the_planned_action() -> None:
    html = str(pages.stepdown_confirm(_status(), _healthy(), force=False))
    assert "This releases leadership on node-a." in html
    assert "Nodes that can take over now: node-b." in html
    assert 'method="post" action="/ui/cluster/stepdown"' in html
    assert not _offers(html, "/ui/cluster/force-stepdown")


def test_the_planned_confirm_points_at_the_forced_drain_when_nothing_could_take_over() -> None:
    alone = _nodes(_node("node-a", is_leader=True), _node("node-b", promotable=False))
    html = str(pages.stepdown_confirm(_status(), alone, force=False))
    assert "the engine would refuse a planned stepdown" in html
    assert f'href="{FORCE_CONFIRM}"' in html


def test_the_force_confirm_states_the_consequence_truthfully() -> None:
    alone = _nodes(_node("node-a", is_leader=True))
    html = str(pages.stepdown_confirm(_status(), alone, force=True))
    assert "nothing does leader work until a node takes the lease" in html
    # The engine renews a force-drained node's own lease when nothing else takes it, so the page must
    # not promise a drain that stays drained.
    assert "A forced drain does not stay drained" in html
    assert "stop the service" in html
    assert 'method="post" action="/ui/cluster/force-stepdown"' in html
    assert not _offers(html, "/ui/cluster/stepdown")


def test_a_confirm_page_whose_control_went_stale_offers_no_form() -> None:
    html = str(pages.stepdown_confirm(_status("node-b", is_leader=False), _healthy(), force=False))
    assert not _offers(html, "/ui/cluster/stepdown")
    assert "open the console on the leader, node-a" in html


def test_each_refusal_renders_its_own_guidance() -> None:
    by_status = {
        s: str(pages.stepdown_refused(s, f"engine says {s}")) for s in (400, 409, 412, 503)
    }
    headlines = {s: _h1(html) for s, html in by_status.items()}
    assert len(set(headlines.values())) == len(headlines), headlines
    for s, html in by_status.items():
        assert f"engine says {s}" in html  # the engine's own detail, verbatim
        assert f"status {s}" in html
    # A 412 is not a wrong-node answer, so its page must not send the operator to find a leader...
    assert "not a wrong-node answer" in by_status[412]
    assert "open the console there" not in by_status[412]
    assert f'href="{FORCE_CONFIRM}"' in by_status[412]
    # ...while a 409 does, with the one case where it is the failover having worked.
    assert "open the console there" in by_status[409]
    assert "healthy successor" in by_status[409]
    assert "Do not retry in a loop" in by_status[503]
    assert "There is no leadership lease to release" in by_status[400]


def test_the_notice_is_selected_by_code_never_supplied_by_the_query() -> None:
    plain = str(pages.high_availability(_status(), _healthy(), can_control=True))
    released = pages.high_availability(_status(), _healthy(), can_control=True, notice="released")
    drained = pages.high_availability(_status(), _healthy(), can_control=True, notice="drained")
    assert "Leadership released." in str(released)
    assert "Leadership released with force" in str(drained)
    hostile = pages.high_availability(_status(), _healthy(), can_control=True, notice="<b>x</b>")
    assert str(hostile) == plain


def test_the_page_takeover_rule_matches_the_engine_stepdown_check() -> None:
    """The console never imports ``pipeline/``, so the page re-applies ``has_promotable_sibling`` to
    the ``ClusterNode`` fields. This holds the copy to the engine's function over every combination of
    the three fields it reads, so a change on either side fails here instead of letting a confirm page
    name a successor the engine then refuses with ``412``."""
    agreed_on_a_successor = False
    for status, promotable, fresh in itertools.product(
        ("active", "left"), (True, False), (True, False)
    ):
        sibling = replace(_member("node-b"), status=status, promotable=promotable, fresh=fresh)
        members = [_member("node-a", is_leader=True), sibling]
        # The same mapping the API applies at its boundary: one ClusterNode per ClusterMember.
        nodes = _nodes(*(ClusterNode.model_validate(asdict(m)) for m in members))
        engine_says = has_promotable_sibling(members, "node-a")
        assert bool(_takeover_candidates(nodes, excluding="node-a")) == engine_says, sibling
        agreed_on_a_successor = agreed_on_a_successor or engine_says
    # Positive control: without it, two rules that both always answered False would agree above.
    assert agreed_on_a_successor


def test_the_quoted_stepdown_pause_matches_the_engine_default() -> None:
    """The force confirm page quotes the stepdown pause at the shipped default. Pinned to the engine's
    own arithmetic and default, so retuning either fails here instead of leaving the page wrong."""
    seconds = stepdown_pause_seconds(ClusterSettings().heartbeat_seconds)
    html = " ".join(str(pages.stepdown_confirm(_status(), _healthy(), force=True)).split())
    assert f"({seconds:g} seconds at the shipped default)" in html


# --- the routes, against a real engine --------------------------------------------------------------


def _member(
    node_id: str, *, is_leader: bool = False, promotable: bool = True, fresh: bool = True
) -> ClusterMember:
    return ClusterMember(
        node_id=node_id,
        host="h",
        pid=1,
        started_at=1.0,
        last_seen=2.0,
        status="active",
        is_leader=is_leader,
        promotable=promotable,
        fresh=fresh,
    )


class _Coordinator(NullCoordinator):
    """A coordinator stand-in whose answers each test sets. Subclasses :class:`NullCoordinator`, the
    house pattern, so only the answers varied here are written here."""

    def __init__(
        self,
        *,
        clustered: bool = True,
        members: list[ClusterMember] | None = None,
        step_down: tuple[bool, float | None] = (True, 1_700_000_000.5),
        raises: Exception | None = None,
    ) -> None:
        super().__init__("node-a")
        self._clustered = clustered
        self._members = (
            members
            if members is not None
            else [_member("node-a", is_leader=True), _member("node-b")]
        )
        self._step_down = step_down
        self._raises = raises
        self.step_down_calls = 0

    def is_clustered(self) -> bool:
        return self._clustered

    async def cluster_members(self) -> list[ClusterMember]:
        return self._members

    async def leadership_lease(self) -> tuple[str | None, float | None]:
        return ("node-a", 1_700_000_030.0) if self._clustered else (self.node_id, None)

    async def step_down_leadership(self) -> tuple[bool, float | None]:
        self.step_down_calls += 1
        if self._raises is not None:
            raise self._raises
        return self._step_down


@asynccontextmanager
async def _console(
    tmp_path: Path,
    coordinator: _Coordinator,
    *,
    role: Role = Role.ADMINISTRATOR,
    settings: AuthSettings | None = None,
) -> AsyncIterator[tuple[Engine, httpx.AsyncClient]]:
    """A started engine holding ``coordinator`` and a browser tab signed in as ``role``."""
    engine = await Engine.create(tmp_path / "ha.db", poll_interval=0.02, coordinator=coordinator)
    await engine.start()
    try:
        service = AuthService(engine.store, settings or AuthSettings(require_mfa=False))
        await service.initialize()
        user_id = await service.create_local_user(
            username="u",
            password=PW,
            display_name=None,
            email=None,
            roles=[role.value],
            actor="test",
        )
        user = await service.store.get_user(user_id)
        assert user is not None and user.password_hash is not None
        await service.store.set_password(
            user_id, password_hash=user.password_hash, must_change_password=False
        )
        transport = httpx.ASGITransport(app=create_app(engine, auth=service, serve_ui=True))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            await client.post("/ui/login", data={"username": "u", "password": PW})
            # The login answers 303 whether or not the password was right, so a gated read is the proof.
            assert (await client.get("/ui/cluster")).status_code == 200
            yield engine, client
    finally:
        await engine.stop()


async def _stepdown_rows(engine: Engine) -> list[dict[str, object]]:
    return [
        r for r in await engine.store.list_audit(limit=200) if r["action"] == "cluster_stepdown"
    ]


async def test_a_monitoring_reader_sees_the_page_but_cannot_reach_the_control(
    tmp_path: Path,
) -> None:
    coord = _Coordinator()
    async with _console(tmp_path, coord, role=Role.OPERATOR) as (_engine, c):
        page_ = await c.get("/ui/cluster")
        assert "<h1>High Availability</h1>" in page_.text
        # An operator reads the page and is told why the control is off.
        assert "needs the cluster:control permission" in page_.text
        assert not _offers(page_.text, CONFIRM)
        live = await c.get("/ui/cluster/live")
        assert live.status_code == 200
        assert 'id="ha-live"' in live.text and "<html" not in live.text
        # The page swaps this fragment in every 5 seconds and the fragment reads the permission for
        # itself, so the page's refusal above holds only until the first refresh unless this does.
        assert not _offers(live.text, CONFIRM)
        # Listed in the nav, so the page is reachable from every other page.
        assert 'href="/ui/cluster"' in (await c.get("/ui/status")).text
        # The gate behind the disabled buttons refuses the same caller on every control route.
        for method, path in (
            ("GET", CONFIRM),
            ("GET", FORCE_CONFIRM),
            ("POST", "/ui/cluster/stepdown"),
            ("POST", "/ui/cluster/force-stepdown"),
        ):
            r = await c.request(method, path, headers=SAME_ORIGIN)
            assert r.status_code == 403, (method, path)
    assert coord.step_down_calls == 0


async def test_a_stale_step_up_returns_to_the_confirm_page_never_the_post(tmp_path: Path) -> None:
    """A stepdown is never auto-re-POSTed across a re-auth. Both its POST and its confirm page send a
    stale session to re-verify with the CONFIRM page as the continuation, so the operator reads the
    consequence again before anything moves."""
    coord = _Coordinator()
    stale = AuthSettings(require_mfa=False, step_up_max_age_seconds=-1)
    async with _console(tmp_path, coord, settings=stale) as (_engine, c):
        for post, confirm in (
            ("/ui/cluster/stepdown", CONFIRM),
            ("/ui/cluster/force-stepdown", FORCE_CONFIRM),
        ):
            bounced = await c.post(post, headers=SAME_ORIGIN)
            assert bounced.status_code == 303, post
            assert bounced.headers["location"] == f"/ui/reauth?next={confirm}"
            opened = await c.get(confirm)
            assert opened.status_code == 303, confirm
            assert opened.headers["location"] == f"/ui/reauth?next={confirm}"
            # A registered unlock target, so the re-auth form renders for it instead of bouncing to /ui.
            assert (await c.get("/ui/reauth", params={"next": confirm})).status_code == 200
    assert coord.step_down_calls == 0


async def test_a_stepdown_through_the_console_reaches_the_engine_and_redirects(
    tmp_path: Path,
) -> None:
    coord = _Coordinator()
    async with _console(tmp_path, coord) as (engine, c):
        # A cross-site POST is refused before the engine is touched. It shares this tab rather than
        # starting an engine of its own: require_ui checks provenance BEFORE it charges the admin-write
        # budget, so the refusal leaves the real stepdown below nothing less to spend.
        cross = await c.post("/ui/cluster/stepdown", headers={"Sec-Fetch-Site": "cross-site"})
        assert cross.status_code == 403
        assert coord.step_down_calls == 0

        confirm = await c.get(CONFIRM)
        assert confirm.status_code == 200
        assert _offers(confirm.text, "/ui/cluster/stepdown")
        r = await c.post("/ui/cluster/stepdown", headers=SAME_ORIGIN)
        assert r.status_code == 303, r.text
        assert r.headers["location"] == "/ui/cluster?m=released"
        assert coord.step_down_calls == 1
        rows = await _stepdown_rows(engine)
        assert len(rows) == 1 and rows[0]["actor"] == "u"
        assert json.loads(str(rows[0]["detail"]))["force"] is False
        assert "Leadership released." in (await c.get(r.headers["location"])).text


async def test_a_forced_drain_of_the_last_node_carries_the_drain_notice(tmp_path: Path) -> None:
    coord = _Coordinator(members=[_member("node-a", is_leader=True)])
    async with _console(tmp_path, coord) as (engine, c):
        r = await c.post("/ui/cluster/force-stepdown", headers=SAME_ORIGIN)
        assert r.status_code == 303, r.text
        assert r.headers["location"] == "/ui/cluster?m=drained"
        detail = json.loads(str((await _stepdown_rows(engine))[0]["detail"]))
        assert detail["force"] is True and detail["new_leader_eligible"] is False


@pytest.mark.parametrize(
    ("make", "status", "headline", "calls"),
    [
        (lambda: _Coordinator(clustered=False), 400, "This engine is not clustered", 0),
        (lambda: _Coordinator(step_down=(False, None)), 409, "This node is not the leader", 1),
        (
            lambda: _Coordinator(
                members=[_member("node-a", is_leader=True), _member("node-b", fresh=False)]
            ),
            412,
            "No other node could take over",
            0,
        ),
        (
            lambda: _Coordinator(raises=StepdownLockTimeout("the leadership lock was still held")),
            503,
            "The stepdown did not finish",
            1,
        ),
        (
            lambda: _Coordinator(raises=StepdownReleaseUnconfirmed("the write did not return")),
            503,
            "The stepdown did not finish",
            1,
        ),
    ],
    ids=["400-not-clustered", "409-not-leader", "412-no-sibling", "503-lock", "503-unconfirmed"],
)
async def test_each_engine_refusal_renders_its_own_page(
    tmp_path: Path, make: Callable[[], _Coordinator], status: int, headline: str, calls: int
) -> None:
    coord = make()
    async with _console(tmp_path, coord) as (_engine, c):
        r = await c.post("/ui/cluster/stepdown", headers=SAME_ORIGIN)
    assert r.status_code == status, r.text
    assert f"<h1>{headline}</h1>" in r.text
    assert f"Engine message (status {status})" in r.text
    assert coord.step_down_calls == calls
