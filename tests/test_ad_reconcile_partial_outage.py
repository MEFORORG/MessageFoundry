# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A lasting PARTIAL directory outage pages (BACKLOG #3709 step 1, #4772 item 6).

Before this, one answered probe ended the outage run, so a directory that answered for some
accounts and never for the rest paged nobody. Each test drives the reconciler through the real
auth service and the lifespan task's alerting, over the fake directory
``tests/test_ad_session_reconcile.py`` defines, with two signed-in accounts: ``alice`` and
``bob``. A partial pass leaves ``alice`` unreachable and answers ``bob``.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from messagefoundry.api.app import _OUTAGE_ALERT_SOURCE, _PARTIAL_OUTAGE_ALERT_SOURCE
from messagefoundry.auth import reconcile
from messagefoundry.auth.ldap import PAGING_DEADLINE_SPENT, LdapUnansweredError
from messagefoundry.store.store import MessageStore
from tests.test_ad_session_reconcile import _outage_service, _pass
from tests.test_ad_user_account_control import _InverseSink

_ROW = "auth.ad_reconcile_partial_outage"
_BOTH = {"alice", "bob"}


def _events(sink: _InverseSink, source: str) -> list[tuple[str, dict[str, Any]]]:
    return [(kind, fields) for kind, name, fields in sink.events if name == source]


def _pages(sink: _InverseSink, source: str) -> list[dict[str, Any]]:
    return [fields for kind, fields in _events(sink, source) if kind == "ad_reconcile_aborted"]


def _clears(sink: _InverseSink, source: str) -> int:
    return sum(1 for kind, _ in _events(sink, source) if kind == "ad_reconcile_breaker_cleared")


async def _rows(store: MessageStore) -> list[dict[str, Any]]:
    return [json.loads(str(r["detail"])) for r in await store.list_audit(action=_ROW)]


@pytest.mark.parametrize("threshold", [2, 3, 5])
async def test_a_lasting_partial_outage_pages_once_and_a_full_answer_resolves_it(
    threshold: int,
) -> None:
    """``threshold`` passes that each reach the directory for ``bob`` only page once, under the
    partial outage's own source; N-1 page nothing; one more pages nothing more; the first pass
    whose every probe is answered resolves it. The whole outage's instance is never touched.

    RED when: one answered probe ends the run again, so a partial outage never pages."""
    store = await MessageStore.open(":memory:")
    try:
        service, ldap = await _outage_service(store, ad_reconcile_outage_passes=threshold)
        sink = _InverseSink()
        ldap.unreachable = {"alice"}
        for n in range(1, threshold):
            plan = await _pass(service, sink)
            assert not plan.directory_outage and plan.aborted is None
            assert (plan.partial_outage_passes, plan.unreached) == (n, 1)
            assert not plan.partial_outage_page
        assert _pages(sink, _PARTIAL_OUTAGE_ALERT_SOURCE) == []  # the N-1 control
        assert await _rows(store) == []

        plan = await _pass(service, sink)
        assert plan.partial_outage_page and plan.partial_outage_passes == threshold
        [page] = _pages(sink, _PARTIAL_OUTAGE_ALERT_SOURCE)
        assert page["reason"] == "directory_partly_unavailable" and page["probed"] == 2
        assert f"on {threshold} probes running (1 of 2 unanswered this pass)" in page["detail"]
        assert len(page["detail"]) <= 200  # the store keeps 200 characters of a reason
        assert await _rows(store) == [
            {
                "reason": "directory_partly_unavailable",
                "unreached": 1,
                "asked": 2,
                "passes": threshold,
            }
        ]

        await _pass(service, sink)  # one more partial pass after firing
        assert len(_pages(sink, _PARTIAL_OUTAGE_ALERT_SOURCE)) == 1
        assert len(await _rows(store)) == 1

        ldap.unreachable = set()  # every probe is answered again
        plan = await _pass(service, sink)
        assert plan.partial_outage_clear and plan.partial_outage_passes == 0
        assert _clears(sink, _PARTIAL_OUTAGE_ALERT_SOURCE) == 1
        assert _events(sink, _OUTAGE_ALERT_SOURCE) == []  # not a whole outage at any point
    finally:
        await store.close()


async def test_a_fully_answered_pass_restarts_the_partial_run() -> None:
    """Two short partial runs with a fully answered pass between them never add up to a page,
    and with nothing paged nothing resolves.

    RED when: the count survives a pass whose every probe was answered."""
    store = await MessageStore.open(":memory:")
    try:
        service, ldap = await _outage_service(store)  # the default, 3
        sink = _InverseSink()
        for _run in range(2):
            ldap.unreachable = {"alice"}
            for _ in range(2):
                assert (await _pass(service, sink)).unreached == 1
            ldap.unreachable = set()
            plan = await _pass(service, sink)
            assert plan.partial_outage_passes == 0 and not plan.partial_outage_clear
        assert _events(sink, _PARTIAL_OUTAGE_ALERT_SOURCE) == []
    finally:
        await store.close()


async def test_whole_and_partial_passes_in_turn_still_page() -> None:
    """A whole pass extends the partial run, so a directory that alternates whole and partial
    passes pages, on the first partial pass once the run is long enough. A partial pass ends the
    whole run, as before, so the whole outage itself never pages here.

    RED when: either kind of pass ends the other's run, so alternating passes page nobody."""
    store = await MessageStore.open(":memory:")
    try:
        service, ldap = await _outage_service(store)  # the default, 3
        sink = _InverseSink()
        shapes = [_BOTH, {"alice"}, _BOTH, {"alice"}]
        plans = []
        for unreachable in shapes:
            ldap.unreachable = set(unreachable)
            plans.append(await _pass(service, sink))
        assert [p.partial_outage_passes for p in plans] == [1, 2, 3, 4]
        assert [p.outage_passes for p in plans] == [1, 0, 1, 0]
        # The third pass is whole: it reaches the run's length, and it pages as no partial outage.
        assert [p.partial_outage_page for p in plans] == [False, False, False, True]
        assert len(_pages(sink, _PARTIAL_OUTAGE_ALERT_SOURCE)) == 1
        assert _pages(sink, _OUTAGE_ALERT_SOURCE) == []
    finally:
        await store.close()


async def test_a_whole_outage_still_pages_as_before_and_a_partial_pass_after_it_pages_as_one() -> (
    None
):
    """A whole outage pages under its own source alone, as before. The partial pass that ends it
    resolves the whole page and pages the partial outage, since accounts still go unreconciled;
    a fully answered pass then resolves that one.

    RED when: a whole outage also raises the partial page, or the partial pass after it leaves
    nothing open while ``alice`` stays unreachable."""
    store = await MessageStore.open(":memory:")
    try:
        service, ldap = await _outage_service(store, ad_reconcile_outage_passes=2)
        sink = _InverseSink()
        ldap.unreachable = set(_BOTH)
        for _ in range(3):
            plan = await _pass(service, sink)
            assert plan.directory_outage and not plan.partial_outage_page
        assert len(_pages(sink, _OUTAGE_ALERT_SOURCE)) == 1
        assert _events(sink, _PARTIAL_OUTAGE_ALERT_SOURCE) == []

        ldap.unreachable = {"alice"}
        plan = await _pass(service, sink)
        assert plan.outage_clear and plan.partial_outage_page
        assert plan.partial_outage_passes == 4
        assert _clears(sink, _OUTAGE_ALERT_SOURCE) == 1
        assert len(_pages(sink, _PARTIAL_OUTAGE_ALERT_SOURCE)) == 1

        ldap.unreachable = set()
        plan = await _pass(service, sink)
        assert plan.partial_outage_clear
        assert _clears(sink, _PARTIAL_OUTAGE_ALERT_SOURCE) == 1
    finally:
        await store.close()


async def test_a_group_search_refused_for_the_engines_bound_is_no_partial_outage() -> None:
    """The directory answered such a probe, and it pages on its own (vault BACKLOG #3696), so a
    pass whose only UNAVAILABLE probe is one reads as fully answered here, and pages no partial
    outage however long it lasts.

    RED when: a standing paging refusal also opens a partial outage that never resolves."""
    store = await MessageStore.open(":memory:")
    try:
        service, ldap = await _outage_service(store, ad_reconcile_outage_passes=2)
        sink = _InverseSink()
        ldap.broken = {
            "alice": LdapUnansweredError(
                "synthetic: the group search was refused", code_name=PAGING_DEADLINE_SPENT
            )
        }
        for _ in range(3):
            plan = await _pass(service, sink)
            assert plan.unavailable == 1 and plan.unreached == 0
            assert plan.partial_outage_passes == 0
        assert _events(sink, _PARTIAL_OUTAGE_ALERT_SOURCE) == []
    finally:
        await store.close()


async def test_a_partial_threshold_pass_that_raises_pages_on_the_next_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The partial page is latched only once its pass's rows are written, as the whole outage's
    is, so a pass that raises first leaves the next partial pass to page.

    RED when: the latch is set before the pass can raise, so the run never pages."""
    store = await MessageStore.open(":memory:")
    try:
        service, ldap = await _outage_service(store, ad_reconcile_outage_passes=2)
        sink = _InverseSink()
        ldap.unreachable = {"alice"}
        await _pass(service, sink)
        real = service._record_reconcile_hold

        async def boom(plan: reconcile.ReconcilePlan) -> None:
            raise RuntimeError("synthetic: store refused")

        monkeypatch.setattr(service, "_record_reconcile_hold", boom)
        with pytest.raises(RuntimeError):
            await service.reconcile_directory_sessions()
        monkeypatch.setattr(service, "_record_reconcile_hold", real)
        plan = await _pass(service, sink)
        assert plan.partial_outage_page and plan.partial_outage_passes == 3
        assert len(_pages(sink, _PARTIAL_OUTAGE_ALERT_SOURCE)) == 1
        await _pass(service, sink)
        assert len(_pages(sink, _PARTIAL_OUTAGE_ALERT_SOURCE)) == 1
    finally:
        await store.close()


async def test_a_probe_budget_smaller_than_the_estate_cannot_reset_an_accounts_run() -> None:
    """Review round 1. With a budget of one probe a pass, ``alice`` and ``bob`` are probed in
    turn, so every other pass answers its only probe. Counted per pass, those passes would end the
    run and nothing would page; counted per account, ``alice``'s run grows on each of her probes,
    pages once it is long enough, and stays open while she is unanswered.

    RED when: a pass that did not probe the unanswered account ends its run."""
    store = await MessageStore.open(":memory:")
    try:
        service, ldap = await _outage_service(
            store, ad_reconcile_outage_passes=2, ad_session_recheck_max_users=1
        )
        sink = _InverseSink()
        ldap.unreachable = {"alice"}
        plans = [await _pass(service, sink) for _ in range(6)]
        assert all(p.asked == 1 for p in plans)
        assert plans[-1].partial_outage_passes == 3
        assert sum(p.partial_outage_page for p in plans) == 1
        assert len(_pages(sink, _PARTIAL_OUTAGE_ALERT_SOURCE)) == 1
        assert _clears(sink, _PARTIAL_OUTAGE_ALERT_SOURCE) == 0  # bob's passes resolve nothing
    finally:
        await store.close()


async def test_one_off_failures_on_different_accounts_never_add_up() -> None:
    """Review round 1. Each pass leaves one probe unanswered, never the same account twice
    running, so no account's run passes one and nothing pages.

    RED when: the run counts passes with any failure rather than one account's failures."""
    store = await MessageStore.open(":memory:")
    try:
        service, ldap = await _outage_service(store, ad_reconcile_outage_passes=2)
        sink = _InverseSink()
        for name in ("alice", "bob", "alice", "bob"):
            ldap.unreachable = {name}
            plan = await _pass(service, sink)
            assert plan.unreached == 1 and plan.partial_outage_passes == 1
        assert _events(sink, _PARTIAL_OUTAGE_ALERT_SOURCE) == []
    finally:
        await store.close()


@pytest.mark.parametrize("beside", ["referred", "faulted"])
async def test_a_pass_that_judged_nothing_but_reached_the_directory_still_pages(
    beside: str,
) -> None:
    """Review round 1. ``bob`` is referred, or his probe faults, on every pass, so each pass
    aborts as a referral or a probe fault and judges nothing. The directory still answered
    ``bob`` and never ``alice``, so the aborted path pages the partial outage and writes its row.

    RED when: the aborted path drops the partial page or its row."""
    store = await MessageStore.open(":memory:")
    try:
        service, ldap = await _outage_service(store, ad_reconcile_outage_passes=2)
        sink = _InverseSink()
        ldap.unreachable = {"alice"}
        if beside == "referred":
            ldap.referring = {"bob"}
        else:
            ldap.broken = {"bob": ValueError("synthetic: unreadable entry")}
        first = await _pass(service, sink)
        second = await _pass(service, sink)
        assert first.aborted is not None and first.judged_nothing
        assert not first.partial_outage_page and second.partial_outage_page
        assert len(_pages(sink, _PARTIAL_OUTAGE_ALERT_SOURCE)) == 1
        assert [r["passes"] for r in await _rows(store)] == [2]
    finally:
        await store.close()
