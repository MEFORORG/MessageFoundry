# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The console's Approvals page: list, approve and reject a dual-control hold (BACKLOG #1982), and
resolve an interrupted release (BACKLOG #2460).

Every hold here is a REAL one, raised through the console's own dead-letter replay by a signed-in
user, so the self-approval refusal is measured against the user id the gate recorded, not a forged
row. The one forged row is the ``interrupted`` release, which no request can produce on demand; it
is built through the store's own transitions, the way ``tests/test_approvals.py`` builds it.
"""

from __future__ import annotations

import re
import time
from typing import get_args
from urllib.parse import quote
from uuid import uuid4

import httpx
from _ui_clients import SAME_ORIGIN, auth_service, cookie_login, provision

from messagefoundry.api import create_app
from messagefoundry.api.models import (
    ApprovalDecisionResult,
    ApprovalList,
    PendingApprovalInfo,
    ResolveOutcome,
)
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import ApprovalsSettings, AuthSettings
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
    async with _client(engine, service, _ON) as maker, _client(engine, service, _ON) as checker:
        await cookie_login(maker, "maker")
        await cookie_login(checker, "checker")
        approval_id = await _hold(maker)
        r = await checker.get("/ui/approvals")
    assert r.status_code == 200
    assert approval_id in r.text
    assert "Replay dead-lettered deliveries" in r.text
    assert f'action="/ui/approvals/{approval_id}/approve"' in r.text
    assert f'action="/ui/approvals/{approval_id}/reject"' in r.text
    # BACKLOG #2458: the row shows what the release would re-run, read from the hold itself.
    assert "Parameters" in r.text
    assert "channel_id: ch1" in r.text
    # A None reads as the scope it means, never as "not set" (an approver would read that as empty).
    assert "destination_name: any destination" in r.text
    # The requester key that only carries the requester to the executor is not a shown parameter.
    assert "requester: maker" not in r.text
    # The nav carries the page under Admin.
    assert 'href="/ui/approvals"' in r.text


async def test_the_requester_cannot_approve_their_own_hold(engine: Engine) -> None:
    service, _maker, _checker = await _two_approvers(engine)
    async with _client(engine, service, _ON) as maker:
        await cookie_login(maker, "maker")
        approval_id = await _hold(maker)
        # BACKLOG #2460: the requester's own row offers Withdraw, not Approve.
        listing = await maker.get("/ui/approvals")
        assert f'action="/ui/approvals/{approval_id}/approve"' not in listing.text
        assert f'action="/ui/approvals/{approval_id}/reject"' in listing.text
        assert "Withdraw" in listing.text and "A different approver decides it." in listing.text
        # A hand-built POST is still the engine's to refuse.
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
        for verb in ("approve", "reject", "resolve/effects_applied"):
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


async def _interrupted(engine: Engine, maker_id: str) -> str:
    """An ``interrupted`` row raised by ``maker``, built through the store's own transitions."""
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
    return approval_id


def _resolve(approval_id: str, outcome: str = "effects_applied") -> str:
    return f"/ui/approvals/{approval_id}/resolve/{outcome}"


async def test_an_interrupted_release_offers_the_resolve_and_not_approve(engine: Engine) -> None:
    service, maker_id, _checker = await _two_approvers(engine)
    approval_id = await _interrupted(engine, maker_id)
    async with _client(engine, service, _ON) as checker:
        await cookie_login(checker, "checker")
        r = await checker.get("/ui/approvals")
        assert r.status_code == 200
        assert "Interrupted releases" in r.text
        assert approval_id in r.text
        assert f'formaction="{_resolve(approval_id)}"' in r.text
        assert f'formaction="{_resolve(approval_id, "effects_not_applied")}"' in r.text
        # One required box covers both outcomes, so a click is a checked choice.
        assert 'type="checkbox" required' in r.text
        # A submission with no button goes to the page (405 on POST), never to an outcome.
        assert 'action="/ui/approvals"' in r.text
        assert (await checker.post("/ui/approvals", headers=SAME_ORIGIN)).status_code == 405
        assert f"/ui/approvals/{approval_id}/approve" not in r.text
        assert f"/ui/approvals/{approval_id}/reject" not in r.text
        assert "No request is waiting for a second approver." in r.text
        # A hand-made POST gets the gate's 409 as a page, as the page's note predicts.
        forced = await checker.post(f"/ui/approvals/{approval_id}/approve", headers=SAME_ORIGIN)
    assert forced.status_code == 409
    assert await _status(engine, approval_id) == "interrupted"


async def test_a_second_approver_resolves_an_interrupted_release(engine: Engine) -> None:
    """BACKLOG #2460 (a): the console records what an interrupted release did, never re-running it."""
    service, maker_id, _checker = await _two_approvers(engine)
    for outcome, status, notice in (
        ("effects_applied", "resolved_applied", "effects were applied"),
        ("effects_not_applied", "resolved_not_applied", "effects were not applied"),
    ):
        approval_id = await _interrupted(engine, maker_id)
        async with _client(engine, service, _ON) as checker:
            await cookie_login(checker, "checker")
            r = await checker.post(_resolve(approval_id, outcome), headers=SAME_ORIGIN)
            assert r.status_code == 303, r.text
            landed = await checker.get(r.headers["location"])
            assert notice in landed.text
            assert approval_id not in landed.text  # resolved rows leave the open queue
            again = await checker.post(_resolve(approval_id, outcome), headers=SAME_ORIGIN)
            assert again.status_code == 409
        assert await _status(engine, approval_id) == status
    resolved = await engine.store.list_audit(action="approval.resolved")
    assert [row["actor"] for row in resolved] == ["checker", "checker"]
    assert await engine.store.list_audit(action="approval.approved") == []


async def test_the_requester_is_not_offered_and_cannot_resolve(engine: Engine) -> None:
    service, maker_id, _checker = await _two_approvers(engine)
    approval_id = await _interrupted(engine, maker_id)
    async with _client(engine, service, _ON) as maker:
        await cookie_login(maker, "maker")
        listing = await maker.get("/ui/approvals")
        assert approval_id in listing.text
        assert f"/ui/approvals/{approval_id}/resolve/" not in listing.text
        assert "A different approver decides it." in listing.text
        r = await maker.post(_resolve(approval_id), headers=SAME_ORIGIN)
    assert r.status_code == 403
    # The resolve's own guidance, not the approve wording.
    assert "Not recorded" in r.text and "Not released" not in r.text
    assert await _status(engine, approval_id) == "interrupted"


async def test_a_resolve_that_lost_the_race_warns_against_requesting_again(engine: Engine) -> None:
    service, maker_id, _checker = await _two_approvers(engine)
    approval_id = await _interrupted(engine, maker_id)
    async with _client(engine, service, _ON) as checker:
        await cookie_login(checker, "checker")
        first = await checker.post(_resolve(approval_id), headers=SAME_ORIGIN)
        assert first.status_code == 303
        second = await checker.post(_resolve(approval_id), headers=SAME_ORIGIN)
    assert second.status_code == 409
    assert "The release cannot be recorded now" in second.text
    assert "it may already have run" in second.text


async def test_a_stale_step_up_window_resolves_nothing(engine: Engine) -> None:
    """The resolve route asks for the fresh step-up the JSON resolve does. A stale window is sent to
    /ui/reauth, which lands back on the page, and the STORE shows nothing was recorded.

    The landing is the page and never the resolve: /ui/reauth re-POSTs an auto-retry continuation
    without showing it, so a ``next=`` link would let its author choose the recorded outcome."""
    from messagefoundry_webconsole._auth import is_safe_ui_action, is_unlock_action

    stale = AuthService(
        engine.store,
        AuthSettings(
            admin_write_min_interval_seconds=0, require_mfa=False, step_up_max_age_seconds=-1
        ),
    )
    await stale.initialize()
    maker_id = await provision(stale, "maker", [Role.ADMINISTRATOR.value])
    await provision(stale, "checker", [Role.ADMINISTRATOR.value])
    approval_id = await _interrupted(engine, maker_id)
    async with _client(engine, stale, _ON) as checker:
        await cookie_login(checker, "checker")
        r = await checker.post(_resolve(approval_id), headers=SAME_ORIGIN)
    assert r.status_code == 303
    landing = "/ui/approvals?m=choose_again"
    assert r.headers["location"] == f"/ui/reauth?next={quote(landing, safe='/')}"
    # /ui/reauth accepts that landing, and would refuse to re-POST either resolve on its own.
    assert is_unlock_action(landing)
    assert "Nothing was recorded" in str(
        pages.approvals_page(ApprovalList(approvals=[]), notice="choose_again")
    )
    for outcome in get_args(ResolveOutcome):
        assert not is_safe_ui_action(_resolve(approval_id, outcome))
    assert await _status(engine, approval_id) == "interrupted"
    # The resolve and its approval.resolved row are one write (vault BACKLOG #2255), so no row.
    assert await engine.store.list_audit(action="approval.resolved") == []


async def test_a_bad_resolve_is_refused(engine: Engine) -> None:
    service, maker_id, _checker = await _two_approvers(engine)
    approval_id = await _interrupted(engine, maker_id)
    async with _client(engine, service, _ON) as checker:
        await cookie_login(checker, "checker")
        cross = await checker.post(_resolve(approval_id), headers={"Sec-Fetch-Site": "cross-site"})
        unknown_outcome = await checker.post(_resolve(approval_id, "maybe"), headers=SAME_ORIGIN)
    assert cross.status_code == 403
    assert unknown_outcome.status_code == 422
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


def test_every_resolve_outcome_has_a_button_and_a_notice() -> None:
    # One ResolveOutcome alias drives the route, its continuation pattern and these two tables.
    from messagefoundry_webconsole.pages import approvals as page_module

    outcomes = set(get_args(ResolveOutcome))
    assert set(page_module._RESOLVE_LABELS) == outcomes
    assert outcomes <= set(page_module._NOTICES)


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

    unreadable = str(pages.approvals_page(ApprovalList(approvals=[_row(None)])))
    assert ">unreadable<" in unreadable
    # The gate refuses to release a row it cannot read, so the page does not offer Approve.
    assert "/approve" not in unreadable and "/reject" in unreadable
    assert ">none<" in str(pages.approvals_page(ApprovalList(approvals=[_row({})])))
    # The requester carry-over is left out while it repeats the Requester column...
    assert ">none<" in str(
        pages.approvals_page(ApprovalList(approvals=[_row({"requester": "maker"})]))
    )
    # ...and shown when it differs, since the release audits under that value.
    differs = str(pages.approvals_page(ApprovalList(approvals=[_row({"requester": "other"})])))
    assert "requester: other" in differs


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
