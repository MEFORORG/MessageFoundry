# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The console's Approvals page: list, approve and reject a dual-control hold (BACKLOG #1982).

Every hold here is a REAL one, raised through the console's own dead-letter replay by a signed-in
user, so the self-approval refusal is measured against the user id the gate recorded, not a forged
row. The one forged row is the ``interrupted`` release, which no request can produce on demand; it
is built through the store's own transitions, the way ``tests/test_approvals.py`` builds it.
"""

from __future__ import annotations

import re
import time
from uuid import uuid4

import httpx
from _ui_clients import SAME_ORIGIN, auth_service, cookie_login, provision

from messagefoundry.api import create_app
from messagefoundry.api.models import ApprovalDecisionResult, ApprovalList, PendingApprovalInfo
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import ApprovalsSettings
from messagefoundry.pipeline import Engine
from messagefoundry_webconsole import pages

#: Dual control on for the replay, with no dwell floor, so a test can approve in the same second.
_ON = ApprovalsSettings(enabled=True, operations=["dead_letter_replay"], min_dwell_seconds=0)

_ID_RE = re.compile(r"Approval id: ([0-9a-f]{32})")


def _client(
    engine: Engine, service: AuthService, approvals: ApprovalsSettings
) -> httpx.AsyncClient:
    app = create_app(engine, auth=service, serve_ui=True, approvals=approvals)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")


async def _two_approvers(engine: Engine) -> tuple[AuthService, str, str]:
    """Two Administrators (the only built-in role holding approvals:approve) and their ids."""
    service = await auth_service(engine)
    maker = await provision(service, "maker", [Role.ADMINISTRATOR.value])
    checker = await provision(service, "checker", [Role.ADMINISTRATOR.value])
    return service, maker, checker


async def _hold(client: httpx.AsyncClient) -> str:
    """Raise a real hold through the console and return its id from the held page."""
    r = await client.post("/ui/dead-letters/ch1/replay", headers=SAME_ORIGIN)
    assert r.status_code == 200, r.status_code
    assert "Replay held for approval" in r.text
    # The held page now points at the page that releases it.
    assert 'href="/ui/approvals"' in r.text
    found = _ID_RE.search(r.text)
    assert found is not None
    return found.group(1)


async def _status(engine: Engine, approval_id: str) -> str:
    row = await engine.store.get_pending_approval(approval_id)
    assert row is not None
    return str(row["status"])


async def test_the_page_lists_a_hold_with_both_buttons(engine: Engine) -> None:
    service, _maker, _checker = await _two_approvers(engine)
    async with _client(engine, service, _ON) as maker:
        await cookie_login(maker, "maker")
        approval_id = await _hold(maker)
        r = await maker.get("/ui/approvals")
    assert r.status_code == 200
    assert approval_id in r.text
    assert "Replay dead-lettered deliveries" in r.text
    assert f'action="/ui/approvals/{approval_id}/approve"' in r.text
    assert f'action="/ui/approvals/{approval_id}/reject"' in r.text
    # BACKLOG #2458: the row shows what the release would re-run, read from the hold itself.
    assert "Parameters" in r.text
    assert "channel_id: ch1" in r.text
    assert "destination_name: not set" in r.text
    # The nav carries the page under Admin.
    assert 'href="/ui/approvals"' in r.text


async def test_the_requester_cannot_approve_their_own_hold(engine: Engine) -> None:
    service, _maker, _checker = await _two_approvers(engine)
    async with _client(engine, service, _ON) as maker:
        await cookie_login(maker, "maker")
        approval_id = await _hold(maker)
        r = await maker.post(f"/ui/approvals/{approval_id}/approve", headers=SAME_ORIGIN)
    # A page, not a 500, carrying the gate's own refusal.
    assert r.status_code == 403
    assert "text/html" in r.headers["content-type"]
    assert "Not released" in r.text
    assert "you cannot approve your own request" in r.text
    assert await _status(engine, approval_id) == "pending"
    assert await engine.store.list_audit(action="approval.approved") == []


async def test_a_second_approver_releases_the_hold(engine: Engine) -> None:
    service, _maker, _checker = await _two_approvers(engine)
    async with _client(engine, service, _ON) as maker, _client(engine, service, _ON) as checker:
        await cookie_login(maker, "maker")
        await cookie_login(checker, "checker")
        approval_id = await _hold(maker)
        r = await checker.post(f"/ui/approvals/{approval_id}/approve", headers=SAME_ORIGIN)
        assert r.status_code == 200
        assert "Request approved" in r.text
        # The operation's own summary survives: a zero-requeue replay says so.
        assert "requeued" in r.text
        assert "maker" in r.text and "checker" in r.text
        assert await _status(engine, approval_id) == "approved"
        rows = await engine.store.list_audit(action="approval.approved")
        assert [row["actor"] for row in rows] == ["checker"]
        # Decided now, so a second approve is a 409 page, not a second run.
        again = await checker.post(f"/ui/approvals/{approval_id}/approve", headers=SAME_ORIGIN)
        assert again.status_code == 409
        assert "The request cannot be decided now" in again.text
        listing = await checker.get("/ui/approvals")
        assert approval_id not in listing.text


async def test_reject_declines_the_hold_and_says_so(engine: Engine) -> None:
    service, _maker, _checker = await _two_approvers(engine)
    async with _client(engine, service, _ON) as maker, _client(engine, service, _ON) as checker:
        await cookie_login(maker, "maker")
        await cookie_login(checker, "checker")
        approval_id = await _hold(maker)
        r = await checker.post(f"/ui/approvals/{approval_id}/reject", headers=SAME_ORIGIN)
        assert r.status_code == 303
        assert r.headers["location"] == "/ui/approvals?m=rejected"
        landed = await checker.get(r.headers["location"])
    assert "Request rejected. The held operation did not run." in landed.text
    assert await _status(engine, approval_id) == "rejected"
    rows = await engine.store.list_audit(action="approval.rejected")
    assert [row["actor"] for row in rows] == ["checker"]


async def test_the_requester_may_withdraw_their_own_hold(engine: Engine) -> None:
    # The gate lets any approver reject, including the requester cancelling their own request.
    service, _maker, _checker = await _two_approvers(engine)
    async with _client(engine, service, _ON) as maker:
        await cookie_login(maker, "maker")
        approval_id = await _hold(maker)
        r = await maker.post(f"/ui/approvals/{approval_id}/reject", headers=SAME_ORIGIN)
    assert r.status_code == 303
    assert await _status(engine, approval_id) == "rejected"


async def test_a_too_new_hold_is_a_409_page_with_its_wait(engine: Engine) -> None:
    service, _maker, _checker = await _two_approvers(engine)
    floor = ApprovalsSettings(enabled=True, operations=["dead_letter_replay"], min_dwell_seconds=60)
    async with _client(engine, service, floor) as maker, _client(engine, service, floor) as checker:
        await cookie_login(maker, "maker")
        await cookie_login(checker, "checker")
        approval_id = await _hold(maker)
        r = await checker.post(f"/ui/approvals/{approval_id}/approve", headers=SAME_ORIGIN)
    assert r.status_code == 409
    assert "too new to approve" in r.text
    # The gate's Retry-After rides through to the browser.
    assert int(r.headers["retry-after"]) > 0
    assert await _status(engine, approval_id) == "pending"


async def test_an_operator_without_approvals_approve_is_refused(engine: Engine) -> None:
    service = await auth_service(engine)
    await provision(service, "admin", [Role.ADMINISTRATOR.value])
    await provision(service, "op", [Role.OPERATOR.value])
    async with _client(engine, service, _ON) as admin, _client(engine, service, _ON) as op:
        await cookie_login(admin, "admin")
        await cookie_login(op, "op")
        approval_id = await _hold(admin)
        assert (await op.get("/ui/approvals")).status_code == 403
        for verb in ("approve", "reject"):
            r = await op.post(f"/ui/approvals/{approval_id}/{verb}", headers=SAME_ORIGIN)
            assert r.status_code == 403
    assert await _status(engine, approval_id) == "pending"


async def test_a_cross_site_post_is_refused(engine: Engine) -> None:
    service, _maker, _checker = await _two_approvers(engine)
    async with _client(engine, service, _ON) as maker, _client(engine, service, _ON) as checker:
        await cookie_login(maker, "maker")
        await cookie_login(checker, "checker")
        approval_id = await _hold(maker)
        for verb in ("approve", "reject"):
            r = await checker.post(
                f"/ui/approvals/{approval_id}/{verb}", headers={"Sec-Fetch-Site": "cross-site"}
            )
            assert r.status_code == 403
    assert await _status(engine, approval_id) == "pending"


async def test_no_bound_gate_is_a_503_page(engine: Engine) -> None:
    # The handlers answer 503 when no gate is bound. An app with an engine always binds one, so the
    # state is set by hand; the dependency reads it per request.
    service = await auth_service(engine)
    await provision(service, "admin", [Role.ADMINISTRATOR.value])
    app = create_app(engine, auth=service, serve_ui=True)
    app.state.approval_gate = None
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as admin:
        await cookie_login(admin, "admin")
        listing = await admin.get("/ui/approvals")
        approve = await admin.post(f"/ui/approvals/{uuid4().hex}/approve", headers=SAME_ORIGIN)
    for r in (listing, approve):
        assert r.status_code == 503
        assert "Dual control is not available" in r.text
        assert "approval workflow is not available" in r.text


async def test_an_unknown_id_is_a_404_page_and_a_malformed_one_is_refused(engine: Engine) -> None:
    service = await auth_service(engine)
    await provision(service, "admin", [Role.ADMINISTRATOR.value])
    async with _client(engine, service, _ON) as admin:
        await cookie_login(admin, "admin")
        unknown = await admin.post(f"/ui/approvals/{uuid4().hex}/approve", headers=SAME_ORIGIN)
        # The JSON route's own ResourceId type, re-applied because the direct call skips it.
        malformed = await admin.post("/ui/approvals/NOT-AN-ID/reject", headers=SAME_ORIGIN)
    assert unknown.status_code == 404
    assert "No such request" in unknown.text
    assert malformed.status_code == 422


async def test_an_interrupted_release_is_listed_without_buttons(engine: Engine) -> None:
    service, maker_id, _checker = await _two_approvers(engine)
    approval_id = uuid4().hex
    await engine.store.create_pending_approval(
        approval_id=approval_id,
        operation="dead_letter_replay",
        params="{}",
        requester="maker",
        requester_user_id=maker_id,
        requested_at=time.time() - 60.0,
        expires_at=None,
    )
    now = time.time()
    assert await engine.store.decide_pending_approval(
        approval_id, status="executing", approver="checker", decided_at=now
    )
    assert await engine.store.decide_pending_approval(
        approval_id,
        status="interrupted",
        approver="checker",
        decided_at=now,
        from_status="executing",
    )
    async with _client(engine, service, _ON) as checker:
        await cookie_login(checker, "checker")
        r = await checker.get("/ui/approvals")
        assert r.status_code == 200
        assert "Interrupted releases" in r.text
        assert approval_id in r.text
        assert f"/ui/approvals/{approval_id}/" not in r.text
        assert "No request is waiting for a second approver." in r.text
        # A hand-made POST gets the gate's 409 as a page, as the page's note predicts.
        forced = await checker.post(f"/ui/approvals/{approval_id}/approve", headers=SAME_ORIGIN)
    assert forced.status_code == 409
    assert await _status(engine, approval_id) == "interrupted"


def test_the_page_escapes_what_it_renders() -> None:
    row = PendingApprovalInfo(
        id="a" * 32,
        operation="dead_letter_replay",
        label="<script>alert(1)</script>",
        requester="<b>maker</b>",
        requested_at=0.0,
        params={"config_dir": "<i>dir</i>", "scope": ["<u>all</u>"]},
    )
    html = str(pages.approvals_page(ApprovalList(approvals=[row])))
    assert "<script>alert(1)</script>" not in html
    assert "<b>maker</b>" not in html
    assert "&lt;b&gt;maker&lt;/b&gt;" in html
    # Captured params are escaped like every other value (BACKLOG #2458).
    assert "<i>dir</i>" not in html and "config_dir: &lt;i&gt;dir&lt;/i&gt;" in html
    assert "<u>all</u>" not in html


def test_params_that_did_not_parse_or_are_empty_say_so() -> None:
    def _row(params: dict[str, object] | None) -> PendingApprovalInfo:
        return PendingApprovalInfo(
            id="b" * 32,
            operation="dead_letter_replay",
            label="replay",
            requester="maker",
            requested_at=0.0,
            params=params,
        )

    assert ">unreadable<" in str(pages.approvals_page(ApprovalList(approvals=[_row(None)])))
    assert ">none<" in str(pages.approvals_page(ApprovalList(approvals=[_row({})])))


def test_a_notice_code_selects_a_sentence_and_never_supplies_one() -> None:
    empty = ApprovalList(approvals=[])
    assert "Request rejected" in str(pages.approvals_page(empty, notice="rejected"))
    assert "anything" not in str(pages.approvals_page(empty, notice="anything"))


def test_a_release_that_did_no_work_says_so() -> None:
    # A purge released while its outbound still runs skips, and the request is closed anyway.
    def _page(result: dict[str, object]) -> str:
        outcome = ApprovalDecisionResult(
            operation="connection_purge", requested_by="maker", approved_by="checker", result=result
        )
        return str(pages.approval_approved(outcome))

    skipped = _page({"cancelled": 0, "skipped": "outbound running"})
    assert "The operation skipped its work: outbound running." in skipped
    degraded = _page({"inbound": 1, "outbound": 1, "degraded": True, "failures": ["audit"]})
    assert "at least one follow-on step failed" in degraded
    clean = _page({"requeued": 2})
    assert "skipped its work" not in clean and "follow-on step failed" not in clean


def test_a_bulk_purge_with_a_held_destination_links_to_approvals() -> None:
    # The nav links to the page on every render, so look only inside <main>.
    held = str(pages.purge_result("all", [("out1", "held for approval (" + "a" * 32 + ")")]))
    assert 'href="/ui/approvals"' in held.split("<main>", 1)[1]
    purged = str(pages.purge_result("all", [("out1", "purged 0")]))
    assert 'href="/ui/approvals"' not in purged.split("<main>", 1)[1]
