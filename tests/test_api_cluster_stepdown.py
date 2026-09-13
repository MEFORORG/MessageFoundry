# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``POST /cluster/stepdown`` — the planned-failover control plane (ADR 0056 slice 1, BACKLOG #1494).

ADR 0056 AC-9 names this file. It covers the whole status table (200 / 400 / 403 / 409 / 412 / 422 /
503), the shapes of the ``503`` (no engine, a membership read that raised, and a drain the coordinator
could not achieve), the BACKLOG #1509 sibling check and the ``force`` flag that waives it, the
content of the audit row, and — the load-bearing one — that the audited ``was_leader`` comes from what
``step_down_leadership()`` RETURNED and never from a prior ``is_leader()`` read. A fence or a
lost-lease tick can flip leadership between a pre-read and the release, so a pre-read would record a
failover that released nothing.

The discriminating fixture is :class:`_StandinCoordinator`, which lets the two answers DISAGREE. A test
suite whose coordinator always answers the same way on both cannot tell the two implementations apart,
which is the failure mode this file exists to rule out.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth import Permission, Role
from messagefoundry.auth.permissions import (
    BUILTIN_ROLE_PERMISSIONS,
    CUSTOM_ROLE_FORBIDDEN_PERMISSIONS,
    CustomRoleError,
    validate_custom_role_permissions,
)
from messagefoundry.auth.service import AuthService
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.cluster import (
    ClusterCoordinator,
    ClusterMember,
    NullCoordinator,
    StepdownLockTimeout,
    StepdownReleaseUnconfirmed,
)
from messagefoundry.store import MessageStore

PW = "a-strong-test-passphrase"  # >=15 chars, no vendor terms — satisfies the ASVS password policy


def _member(
    node_id: str,
    *,
    is_leader: bool = False,
    status: str = "active",
    promotable: bool = True,
    fresh: bool = True,
) -> ClusterMember:
    """One membership row as a DB coordinator publishes it. ``fresh`` is set directly: the rule that
    computes it belongs to the coordinator, and ``tests/test_cluster.py`` pins that rule."""
    return ClusterMember(
        node_id=node_id,
        host="h",
        pid=1,
        started_at=1.0,
        last_seen=2.0,
        status=status,
        is_leader=is_leader,
        promotable=promotable,
        fresh=fresh,
    )


class _StandinCoordinator(NullCoordinator):
    """A coordinator whose ``is_leader()`` and ``step_down_leadership()`` are set SEPARATELY.

    That separation is the point. ``step_down`` is the tuple the release returns; ``leader`` is what a
    pre-read would have seen. Setting them to disagree reproduces the fence/lost-lease race the ADR
    warns about, and is the only way a test can prove which one the handler audited.

    ``members`` is what the membership read returns, and ``members_raise`` makes that read fail. The
    default carries a live promotable sibling, so a test that is not ABOUT the BACKLOG #1509 refusal
    reaches the coordinator exactly as it did before that refusal existed. ``calls`` records the ORDER
    of the two reads, which a count cannot: the membership read must come first, and only once.

    Subclasses :class:`NullCoordinator` — the house pattern for a coordinator stand-in — so the
    answers these tests vary are the only ones written here, and a future Protocol method does not
    have to be hand-copied in.
    """

    def __init__(
        self,
        *,
        clustered: bool = True,
        leader: bool = True,
        step_down: tuple[bool, float | None] = (True, 1_700_000_000.5),
        raises: Exception | None = None,
        members: list[ClusterMember] | None = None,
        members_raise: Exception | None = None,
    ) -> None:
        super().__init__("node-a")
        self._clustered = clustered
        self._leader = leader
        self._step_down = step_down
        self._raises = raises
        self._members = (
            members
            if members is not None
            else [_member("node-a", is_leader=True), _member("node-b")]
        )
        self._members_raise = members_raise
        self.calls: list[str] = []

    @property
    def step_down_calls(self) -> int:
        return self.calls.count("step_down_leadership")

    def is_leader(self) -> bool:
        return self._leader

    def is_clustered(self) -> bool:
        return self._clustered

    async def cluster_members(self) -> list[ClusterMember]:
        self.calls.append("cluster_members")
        if self._members_raise is not None:
            raise self._members_raise
        return self._members

    async def step_down_leadership(self) -> tuple[bool, float | None]:
        self.calls.append("step_down_leadership")
        if self._raises is not None:
            raise self._raises
        return self._step_down


# --- harness ------------------------------------------------------------------


async def _engine(tmp_path: Path, coordinator: ClusterCoordinator | None = None) -> Engine:
    """A started SQLite engine holding ``coordinator``. ``Engine.create`` is the documented
    tests/embedding path and forwards ``coordinator`` straight through, so nothing here re-implements
    the constructor's keyword list."""
    eng = await Engine.create(tmp_path / "stepdown.db", poll_interval=0.02, coordinator=coordinator)
    await eng.start()
    return eng


async def _service(store: MessageStore, settings: AuthSettings | None = None) -> AuthService:
    service = AuthService(
        store, settings or AuthSettings(require_mfa=False, login_rate_limit_enabled=False)
    )
    await service.initialize()
    return service


def _client(engine: Engine | None, service: AuthService) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))  # type: ignore[arg-type]
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def _add(service: AuthService, username: str, *roles: Role) -> None:
    user_id = await service.create_local_user(
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=[r.value for r in roles],
        actor="test",
    )
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    # Admin-created accounts force first-login rotation; clear it for a usable test login.
    await service.store.set_password(
        user_id, password_hash=user.password_hash, must_change_password=False
    )


async def _login(c: httpx.AsyncClient, username: str) -> str:
    r = await c.post(
        "/auth/login", json={"username": username, "password": PW, "provider": "local"}
    )
    assert r.status_code == 200, r.text
    return str(r.json()["token"])


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _rotated(response: httpx.Response, token: str) -> str:
    """The bearer to use AFTER an elevation call (ASVS 7.2.4).

    A successful elevation re-keys the session and returns the new token in the body, so every later
    request has to carry it -- keeping the old one would 401 and quietly turn a real assertion into a
    test of an expired token. A refusal rotates nothing and the incoming token is handed back. Same
    helper, same wording, as ``tests/test_step_up.py`` and ``tests/test_api_auth.py``."""
    if response.status_code != 200:
        return token
    fresh = response.json().get("token")
    assert isinstance(fresh, str) and fresh, "an elevation route returned no rotated token"
    return fresh


@asynccontextmanager
async def _admin(
    tmp_path: Path,
    coordinator: ClusterCoordinator | None = None,
    settings: AuthSettings | None = None,
) -> AsyncIterator[tuple[Engine, httpx.AsyncClient, str]]:
    """A started engine, an API client, and a signed-in Administrator's bearer token.

    Every test below needs those three and nothing else varies but the coordinator, so the scaffold
    lives here once rather than as a try/finally in each body."""
    engine = await _engine(tmp_path, coordinator)
    try:
        service = await _service(engine.store, settings)
        await _add(service, "boss", Role.ADMINISTRATOR)
        async with _client(engine, service) as c:
            yield engine, c, await _login(c, "boss")
    finally:
        await engine.stop()


async def _rows(engine: Engine, action: str) -> list[dict[str, object]]:
    return [r for r in await engine.store.list_audit(limit=200) if r["action"] == action]


# --- the permission itself ---------------------------------------------------


def test_cluster_control_is_administrator_only() -> None:
    # A dedicated capability, NOT a reuse of monitoring:read (a read) or connections:control (one
    # connection): a planned failover moves the whole cluster's primary (ADR 0056).
    assert Permission.CLUSTER_CONTROL in BUILTIN_ROLE_PERMISSIONS[Role.ADMINISTRATOR]
    for role in (Role.OPERATOR, Role.DEPLOYMENT, Role.CODING, Role.VIEWER, Role.AUDITOR):
        assert Permission.CLUSTER_CONTROL not in BUILTIN_ROLE_PERMISSIONS[role]


def test_cluster_control_not_assignable_to_a_custom_role() -> None:
    # "Administrator only" is enforced on every minting path, not merely observed of the built-ins.
    assert Permission.CLUSTER_CONTROL in CUSTOM_ROLE_FORBIDDEN_PERMISSIONS
    with pytest.raises(CustomRoleError):
        validate_custom_role_permissions(["cluster:control"])


# --- AC-9: the status table + the audit row ----------------------------------


async def test_stepdown_rbac_audit_and_status_codes(tmp_path: Path) -> None:
    """ADR 0056 AC-9, end to end on one clustered node."""
    coord = _StandinCoordinator(clustered=True, leader=True)
    async with _admin(tmp_path, coord) as (engine, c, boss):
        # 403 — an OPERATOR holds connections:control but not cluster:control (deny-by-default), and
        # require_step_up records that denial itself, so the handler never runs.
        service = await _service(engine.store)
        await _add(service, "op", Role.OPERATOR)
        op = await _login(c, "op")
        denied = await c.post("/cluster/stepdown", headers=_auth(op), json={})
        assert denied.status_code == 403
        assert "cluster:control" in denied.json()["detail"]
        assert coord.step_down_calls == 0
        assert any(
            "/cluster/stepdown" in str(row["detail"] or "")
            for row in await engine.store.list_audit(limit=200)
            if "denied" in str(row["action"] or "")
        )

        # 403 — step-up recency. The window is back-dated, so a session that holds the permission is
        # still refused until it re-proves its credential.
        await service.store.mark_session_reauthed(hash_token(boss), now=0.0)
        stale = await c.post("/cluster/stepdown", headers=_auth(boss), json={})
        assert stale.status_code == 403
        assert stale.headers.get("X-Step-Up-Required") == "1"
        assert coord.step_down_calls == 0
        reauth = await c.post("/me/reauth", headers=_auth(boss), json={"password": PW})
        assert reauth.status_code == 200
        # A successful re-auth ROTATES the session (ASVS 7.2.4), so the old bearer stops resolving.
        # Without this rebind every assertion below silently becomes a test of an expired token: the
        # 422 arrives as a 401 and the 200/409 arms never reach the handler at all.
        boss = _rotated(reauth, boss)

        # 422 — an unknown field is refused rather than silently ignored (RequestModel). `force` is a
        # real field now, so the refusal is pinned with a name the model does not carry.
        unknown = await c.post("/cluster/stepdown", headers=_auth(boss), json={"fence": True})
        assert unknown.status_code == 422
        assert coord.step_down_calls == 0

        # 200 — the happy path. The body reports what the coordinator returned, plus what the one
        # membership read found: node-b is a live promotable sibling, so a successor is eligible.
        ok = await c.post("/cluster/stepdown", headers=_auth(boss), json={})
        assert ok.status_code == 200, ok.text
        assert ok.json() == {
            "node_id": "node-a",
            "was_leader": True,
            "released_at": 1_700_000_000.5,
            "new_leader_eligible": True,
            "force": False,
        }
        assert coord.step_down_calls == 1
        # ONE membership read, and BEFORE the release. The 412 decision and new_leader_eligible share
        # it, and it never runs inside the coordinator's leadership lock.
        assert coord.calls == ["cluster_members", "step_down_leadership"]

        # The granted audit row: the acting user, cluster metadata only, no PHI. Its detail is the
        # RESPONSE body itself, so the two cannot drift apart field by field.
        rows = await _rows(engine, "cluster_stepdown")
        assert len(rows) == 1
        assert rows[0]["actor"] == "boss"
        assert rows[0]["channel_id"] is None
        assert json.loads(str(rows[0]["detail"])) == ok.json()

        # 409 — this node is not the leader. The row still records was_leader=false; the handler
        # docstring covers the retry on which this same 409 is the failover succeeding.
        coord._step_down = (False, None)
        conflict = await c.post("/cluster/stepdown", headers=_auth(boss), json={})
        assert conflict.status_code == 409
        assert "not the current leader" in conflict.json()["detail"]
        assert coord.step_down_calls == 2


async def test_stepdown_audits_the_returned_was_leader_not_a_pre_read(tmp_path: Path) -> None:
    # THE DISCRIMINATING CASE. is_leader() says True (what a pre-read would have seen) while the
    # release reports it held nothing — the fence / lost-lease tick landing between the two. A handler
    # that audited the pre-read would write was_leader=true for an action that released nothing, and
    # would answer 200. Both halves are asserted, so neither can drift alone.
    coord = _StandinCoordinator(clustered=True, leader=True, step_down=(False, None))
    async with _admin(tmp_path, coord) as (engine, c, boss):
        r = await c.post("/cluster/stepdown", headers=_auth(boss), json={})
        assert r.status_code == 409
        rows = await _rows(engine, "cluster_stepdown")
        assert len(rows) == 1
        assert json.loads(str(rows[0]["detail"])) == {
            "node_id": "node-a",
            "was_leader": False,
            "released_at": None,
            "new_leader_eligible": True,
            "force": False,
        }


async def test_stepdown_does_not_pre_read_is_leader_at_all(tmp_path: Path) -> None:
    # The mirror of the case above, and the positive control for it: is_leader() says False while the
    # release reports it really did hold the lease. A handler with an is_leader() 409 gate would refuse
    # here without ever calling the coordinator; this one calls it and answers 200.
    coord = _StandinCoordinator(clustered=True, leader=False, step_down=(True, 42.0))
    async with _admin(tmp_path, coord) as (_eng, c, boss):
        r = await c.post("/cluster/stepdown", headers=_auth(boss), json={})
        assert r.status_code == 200, r.text
        assert r.json()["was_leader"] is True and r.json()["released_at"] == 42.0
        assert coord.step_down_calls == 1


async def test_single_node_is_refused_before_the_coordinator_is_touched(tmp_path: Path) -> None:
    # 400 on a single node, gated BEFORE the coordinator (ADR 0056): there is no lease to release and
    # no standby to promote, so the answer must not depend on a NullCoordinator's no-op. The refusal is
    # audited because it is one the HANDLER reaches — require_step_up records the 403s, not this.
    coord = _StandinCoordinator(clustered=False, leader=True)
    async with _admin(tmp_path, coord) as (engine, c, boss):
        r = await c.post("/cluster/stepdown", headers=_auth(boss), json={})
        assert r.status_code == 400
        assert "not clustered" in r.json()["detail"]
        # Not even the membership read: there is no cluster to read.
        assert coord.calls == []
        assert not await _rows(engine, "cluster_stepdown")
        denied = await _rows(engine, "cluster_stepdown_denied")
        assert len(denied) == 1
        assert json.loads(str(denied[0]["detail"])) == {
            "node_id": "node-a",
            "reason": "not-clustered",
        }


async def test_default_single_node_engine_is_refused(tmp_path: Path) -> None:
    # The same 400 through the SHIPPED single-node path (NullCoordinator), not only the stand-in — so
    # the gate is proven against the coordinator an operator actually runs on SQLite. force does not
    # move it: no lease exists, so there is nothing a forced release could expire.
    async with _admin(tmp_path) as (_eng, c, boss):
        r = await c.post("/cluster/stepdown", headers=_auth(boss), json={})
        assert r.status_code == 400
        forced = await c.post("/cluster/stepdown", headers=_auth(boss), json={"force": True})
        assert forced.status_code == 400


# --- BACKLOG #1509: the promotable-sibling refusal, force, new_leader_eligible ---


async def test_a_node_with_no_promotable_sibling_is_refused_before_the_release(
    tmp_path: Path,
) -> None:
    # THE #1509 DEFECT. A clustered deployment with nothing able to take over passed the old
    # is_clustered() gate, released its lease, and sat leaderless for the pause. This stand-in IS
    # clustered and IS the leader, and its only sibling has stopped heartbeating, so only the
    # membership check can refuse it. tests/test_cluster.py walks each disqualifier through the
    # predicate itself.
    coord = _StandinCoordinator(
        members=[_member("node-a", is_leader=True), _member("node-b", fresh=False)]
    )
    async with _admin(tmp_path, coord) as (engine, c, boss):
        r = await c.post("/cluster/stepdown", headers=_auth(boss), json={})
        # 412, deliberately not 409: the node addressed is the right one, and a caller told "wrong
        # node" would go looking for a leader that does not exist.
        assert r.status_code == 412
        detail_text = r.json()["detail"]
        assert "no other promotable node" in detail_text and "changed nothing" in detail_text
        # The remedy names the override, and says plainly that it does not keep the node drained.
        assert '{"force": true}' in detail_text and "does not stay drained" in detail_text
        assert "not the current leader" not in detail_text
        assert coord.calls == ["cluster_members"]
        assert not await _rows(engine, "cluster_stepdown")
        denied = await _rows(engine, "cluster_stepdown_denied")
        assert len(denied) == 1
        assert json.loads(str(denied[0]["detail"])) == {
            "node_id": "node-a",
            "reason": "no-promotable-sibling",
        }
        # The remedy sends the operator to GET /cluster/nodes, so that listing must show the verdict
        # the check used, rather than leave a client to re-derive freshness from last_seen.
        nodes = await c.get("/cluster/nodes", headers=_auth(boss))
        assert nodes.status_code == 200, nodes.text
        assert {n["node_id"]: n["fresh"] for n in nodes.json()["nodes"]} == {
            "node-a": True,
            "node-b": False,
        }


async def test_force_drains_the_last_node_and_reports_no_eligible_successor(
    tmp_path: Path,
) -> None:
    # The operator who drains the last node on purpose. force waives the 412, and the body and the
    # audit row both say no successor was eligible and that the override was used, so the record shows
    # why a leaderless window followed.
    coord = _StandinCoordinator(members=[_member("node-a", is_leader=True)])
    async with _admin(tmp_path, coord) as (engine, c, boss):
        r = await c.post("/cluster/stepdown", headers=_auth(boss), json={"force": True})
        assert r.status_code == 200, r.text
        assert r.json() == {
            "node_id": "node-a",
            "was_leader": True,
            "released_at": 1_700_000_000.5,
            "new_leader_eligible": False,
            "force": True,
        }
        assert coord.calls == ["cluster_members", "step_down_leadership"]
        rows = await _rows(engine, "cluster_stepdown")
        assert len(rows) == 1
        assert json.loads(str(rows[0]["detail"])) == r.json()
        assert not await _rows(engine, "cluster_stepdown_denied")


async def test_force_with_a_live_sibling_reports_both_fields_true(tmp_path: Path) -> None:
    # The one 200 on which the two fields are not each other's negation (BACKLOG #1524). force=false
    # reaches a 200 only with an eligible sibling, since eligible=false plus force=false is the 412, so
    # every other 200 here has new_leader_eligible == (not force). A handler that reported either field
    # as the negation of the other passed the whole file. force on a node that does have a live
    # promotable sibling is allowed, and then both fields must read true.
    coord = _StandinCoordinator()  # the default members carry node-b, fresh and promotable
    async with _admin(tmp_path, coord) as (engine, c, boss):
        r = await c.post("/cluster/stepdown", headers=_auth(boss), json={"force": True})
        assert r.status_code == 200, r.text
        assert r.json() == {
            "node_id": "node-a",
            "was_leader": True,
            "released_at": 1_700_000_000.5,
            "new_leader_eligible": True,
            "force": True,
        }
        assert coord.calls == ["cluster_members", "step_down_leadership"]
        rows = await _rows(engine, "cluster_stepdown")
        assert len(rows) == 1
        assert json.loads(str(rows[0]["detail"])) == r.json()
        assert not await _rows(engine, "cluster_stepdown_denied")


async def test_force_does_not_turn_a_non_leader_into_a_success(tmp_path: Path) -> None:
    # force waives the no-sibling refusal and NOTHING else. On a node whose release reports it held no
    # leadership there is nothing to drain, so the answer is still 409, forced or not.
    coord = _StandinCoordinator(members=[_member("node-a")], step_down=(False, None))
    async with _admin(tmp_path, coord) as (engine, c, boss):
        r = await c.post("/cluster/stepdown", headers=_auth(boss), json={"force": True})
        assert r.status_code == 409
        assert coord.step_down_calls == 1
        rows = await _rows(engine, "cluster_stepdown")
        assert len(rows) == 1
        detail = json.loads(str(rows[0]["detail"]))
        assert detail["was_leader"] is False and detail["force"] is True


async def test_an_unreadable_membership_is_a_503_that_changes_nothing(tmp_path: Path) -> None:
    # #1509's cost, written down rather than discovered: the new read needs the store, so an
    # unreachable store turns the refusal into a 503. The read runs before the release, so nothing
    # ran — and force does not skip it, because its answer is still reported. Both values of force go
    # through one engine: the stand-in keeps no state between the two posts.
    coord = _StandinCoordinator(members_raise=RuntimeError("the pool is not answering"))
    async with _admin(tmp_path, coord) as (engine, c, boss):
        for force in (False, True):
            r = await c.post("/cluster/stepdown", headers=_auth(boss), json={"force": force})
            assert r.status_code == 503, force
            detail_text = r.json()["detail"]
            assert "could not read cluster membership" in detail_text
            assert "changed nothing" in detail_text
            # It asserts nothing about leadership, and borrows neither drain arm's wording.
            assert "still the leader" not in detail_text and "could not confirm" not in detail_text
        assert coord.calls == ["cluster_members", "cluster_members"]
        assert not await _rows(engine, "cluster_stepdown")
        denied = await _rows(engine, "cluster_stepdown_denied")
        assert len(denied) == 2
        for row in denied:
            detail = json.loads(str(row["detail"]))
            assert detail["node_id"] == "node-a" and detail["reason"] == "members-unreadable"
            assert row["actor"] == "boss"


async def test_an_unconfirmed_release_is_503_and_is_not_audited_as_a_stepdown(
    tmp_path: Path,
) -> None:
    # The failure the coordinator can no longer hide. If the write did not land, the lease row is live
    # and still owned by a node that has already demoted, so no standby can take it. Reporting
    # 200/was_leader=true there would send an operator into a node that may still hold the lease,
    # which is the whole point of asking.
    #
    # 503, not 409 or 500: this is an ENVIRONMENT condition, the status the neighbouring DR endpoints
    # and ADR 0056's own contract already give those. 409 would be wrong in the other direction -- it
    # says "you addressed the wrong node", and the caller would go and address a different one.
    coord = _StandinCoordinator(
        raises=StepdownReleaseUnconfirmed("the lease-expiring write did not return")
    )
    async with _admin(tmp_path, coord) as (engine, c, boss):
        r = await c.post("/cluster/stepdown", headers=_auth(boss), json={})
        assert r.status_code == 503
        detail_text = r.json()["detail"]
        assert coord.step_down_calls == 1

        # CONDITIONAL, because the outcome is genuinely unknown: a lost response to a committed UPDATE
        # is indistinguishable here from an UPDATE that never ran. The retired body asserted "it is
        # still the leader", which on the committed branch sends an operator to fix a cluster that is
        # already failing over correctly.
        assert "could not confirm" in detail_text and "may still own a live lease" in detail_text
        assert "it is still the leader" not in detail_text
        # ...and it says the two things an operator has to act on: a retry is what re-sends the write,
        # and the node is NOT quiescent yet.
        assert "retry" in detail_text.lower()
        assert "cleared its leadership flag" in detail_text
        assert "bounded share of the demotion budget" in detail_text
        assert "unbounded" in detail_text and "connector close" in detail_text
        assert "never means the node is quiescent" in detail_text

        # THREE RETIRED CLAIMS, pinned negatively because each shipped once and this test asserted two
        # of them back. They are separate defects and must not be collapsed into one assertion.
        #
        # 1. "stopped serving" — Engine._on_demote_edge only sets _graph_wake and deliberately does not
        #    set the runner's _stop, so a node answering this 503 is still bound to its port and still
        #    ACKing. An operator who read it would begin maintenance on a live node.
        assert "stopped serving" not in detail_text
        # 2. "listeners keep accepting until it completes" — the ordering refutes it.
        #    RegistryRunner._teardown_body runs _stop_sources_demote LAST of the three BOUNDED demote
        #    phases and only THEN reaches the unbounded connector-close, executor-shutdown and
        #    sandbox-close phases; MLLP/TCP/HTTP/X12 each call server.close() in their stop()'s
        #    synchronous prologue. Accept stops EARLIER than that sentence said, not later.
        assert "keep accepting until" not in detail_text
        # 3. "started tearing its graph down" — DbCoordinator.step_down_leadership fires the demotion
        #    edge only under `if was_leader`, which a retry of an owed write has already cleared. On a
        #    repeat refusal no edge fires and no teardown starts, so this body may not assert one did.
        assert "started tearing its graph down" not in detail_text

        # No cluster_stepdown row: nothing was stepped down, and a row carrying was_leader would be
        # answering the wrong question. The denied row records what actually happened.
        assert not await _rows(engine, "cluster_stepdown")
        denied = await _rows(engine, "cluster_stepdown_denied")
        assert len(denied) == 1
        detail = json.loads(str(denied[0]["detail"]))
        assert detail["node_id"] == "node-a" and detail["reason"] == "release-unconfirmed"
        assert denied[0]["actor"] == "boss"


async def test_a_refusal_survives_an_audit_write_that_fails_with_the_store(tmp_path: Path) -> None:
    # THE REFUSAL'S OWN AUDIT ROW GOES THROUGH THE STORE THAT PRODUCED THE REFUSAL. A
    # `release-unconfirmed` is raised only when the lease-expiring write did not return, and on
    # Postgres build_coordinator hands the coordinator `store._pool` -- the same pool record_audit
    # borrows. So the arm most likely to reach this write is exactly the one whose store is sick.
    #
    # Unguarded, that raise unwound past the handler's own `raise HTTPException(503, ...)` and the
    # app's catch-all (`@app.exception_handler(Exception)`) answered a bare 500 "internal error": no
    # reason, no remedy text, and no row either, on a node that has already cleared its leadership flag
    # and may still own a live lease no standby can take. The row is unwritable on both paths, so the
    # guard trades nothing for it.
    #
    # VACUITY CONTROL, MEASURED: remove the try/except around record_audit in the handler's `_denied`
    # and this fails -- but NOT at the status assertion, and the difference is worth knowing before you
    # read a failure here. The measured failure is the RuntimeError propagating out of the POST itself:
    # Starlette routes a handler registered for Exception through ServerErrorMiddleware, which sends
    # the 500 and then RE-RAISES so a server can log it, and httpx.ASGITransport surfaces that raise
    # rather than the response. A real client over uvicorn gets the 500; this harness gets the
    # exception. Either way the composed refusal is gone, which is what the assertions below pin.
    coord = _StandinCoordinator(
        raises=StepdownReleaseUnconfirmed("the lease-expiring write did not return")
    )
    async with _admin(tmp_path, coord) as (engine, c, boss):
        real = engine.store.record_audit

        async def _sick_store(action: str, **kwargs: Any) -> None:
            # Only the denied row fails, so this stands in for a store that broke during the release
            # rather than one that was never usable -- the auth rows written earlier still landed.
            if action == "cluster_stepdown_denied":
                raise RuntimeError("the audit write went to the pool that had already failed")
            await real(action, **kwargs)

        engine.store.record_audit = _sick_store  # type: ignore[method-assign]
        r = await c.post("/cluster/stepdown", headers=_auth(boss), json={})

        # The composed refusal survives intact: the status a caller branches on, and the remedy.
        assert r.status_code == 503, "a failed audit write replaced the refusal with a bare 500"
        detail_text = r.json()["detail"]
        assert "could not confirm" in detail_text and "retry" in detail_text.lower()

        # And the row really is gone. The guard keeps the answer; it does not rescue the row, and the
        # handler's docstring says so rather than leaving a reader to infer the row always lands.
        engine.store.record_audit = real  # type: ignore[method-assign]
        assert not await _rows(engine, "cluster_stepdown_denied")


async def test_a_lock_timeout_is_its_own_503_and_asserts_no_leadership(tmp_path: Path) -> None:
    # THE SECOND RAISE SITE, which used to share the first one's body and audit reason. It fires BEFORE
    # any release runs -- no lease row read, none written, nothing demoted -- and, because the handler
    # deliberately takes no is_leader() pre-read, it can come back from a node that leads nothing. So
    # every sentence the other branch owes the operator is wrong here, and one shared arm gave them
    # both anyway.
    coord = _StandinCoordinator(
        leader=False,  # the node this refusal can reach: it leads nothing
        raises=StepdownLockTimeout("the leadership lock was still held at the fence timeout"),
    )
    async with _admin(tmp_path, coord) as (engine, c, boss):
        r = await c.post("/cluster/stepdown", headers=_auth(boss), json={})
        assert r.status_code == 503
        detail_text = r.json()["detail"]

        # It names the lock and says nothing ran. It must NOT claim this node leads, must NOT claim it
        # demoted, and must not borrow the release branch's language.
        assert "leadership lock" in detail_text and "changed nothing" in detail_text
        assert "still the leader" not in detail_text
        assert "demoted itself" not in detail_text and "could not confirm" not in detail_text

        assert not await _rows(engine, "cluster_stepdown")
        denied = await _rows(engine, "cluster_stepdown_denied")
        assert len(denied) == 1
        detail = json.loads(str(denied[0]["detail"]))
        # A DISTINCT reason, so the audit log can tell an operator which condition they hit. One reason
        # for both would make "was this node drained?" unanswerable from the record.
        assert detail["reason"] == "lock-timeout"


async def test_stepdown_is_503_without_an_engine(tmp_path: Path) -> None:
    # 503 when no engine is bound — the embedded / not-yet-started shape. Auth still needs a store, but
    # the app is built with engine=None, so there is deliberately no Engine here at all.
    store = await MessageStore.open(tmp_path / "no-engine.db")
    try:
        service = await _service(store)
        await _add(service, "boss", Role.ADMINISTRATOR)
        async with _client(None, service) as c:
            boss = await _login(c, "boss")
            r = await c.post("/cluster/stepdown", headers=_auth(boss), json={})
            assert r.status_code == 503
    finally:
        await store.close()


async def test_mfa_pending_session_cannot_step_down(tmp_path: Path) -> None:
    # ADR 0056's decision table asks for step-up PLUS TOTP MFA. require_step_up is the composite that
    # supplies both, so an MFA-required session that has not verified its second factor is refused with
    # X-MFA-Required before anything else — and the coordinator is never called.
    coord = _StandinCoordinator()
    settings = AuthSettings(require_mfa=True, login_rate_limit_enabled=False)
    async with _admin(tmp_path, coord, settings) as (_eng, c, boss):
        r = await c.post("/cluster/stepdown", headers=_auth(boss), json={})
        assert r.status_code == 403
        assert r.headers.get("X-MFA-Required") == "1"
        assert coord.step_down_calls == 0
