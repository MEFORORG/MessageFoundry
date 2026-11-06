# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A lasting PARTIAL directory outage pages (BACKLOG #3709 step 1, #4772 item 6).

Before this, one answered probe ended the outage run, so a directory that answered for some
accounts and never for the rest paged nobody. Each account now has a streak of probes the
directory left unanswered, counted on passes that are not a whole outage. Each test drives the
reconciler through the real auth service and the lifespan task's alerting, over the fake
directory ``tests/test_ad_session_reconcile.py`` defines. A partial pass leaves ``alice``
unreachable and answers the rest; a whole pass answers nobody.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from messagefoundry.api.app import _OUTAGE_ALERT_SOURCE, _PARTIAL_OUTAGE_ALERT_SOURCE
from messagefoundry.auth import reconcile
from messagefoundry.auth.ldap import PAGING_DEADLINE_SPENT, LdapUnansweredError
from messagefoundry.auth.service import AuthService
from messagefoundry.store.store import MessageStore
from tests.test_ad_session_reconcile import (
    _ad_settings,
    _FakeLdap,
    _outage_service,
    _pass,
    _principal,
    _signed_in_ad_user,
)
from tests.test_ad_user_account_control import _InverseSink

_ROW = "auth.ad_reconcile_partial_outage"
_BOTH = {"alice", "bob"}


def _events(sink: _InverseSink, source: str) -> list[tuple[str, dict[str, Any]]]:
    return [(kind, fields) for kind, name, fields in sink.events if name == source]


def _pages(sink: _InverseSink, source: str) -> list[dict[str, Any]]:
    return [fields for kind, fields in _events(sink, source) if kind == "ad_reconcile_aborted"]


def _clears(sink: _InverseSink, source: str) -> int:
    return sum(1 for kind, _ in _events(sink, source) if kind == "ad_reconcile_breaker_cleared")


def _longest(service: AuthService) -> int:
    return max(service._reconcile_unreached.values(), default=0)


async def _rows(store: MessageStore) -> list[dict[str, Any]]:
    return [json.loads(str(r["detail"])) for r in await store.list_audit(action=_ROW)]


async def _estate(
    store: MessageStore, *names: str, **over: object
) -> tuple[AuthService, _FakeLdap]:
    ldap = _FakeLdap({name: _principal(name) for name in names})
    service = AuthService(store, _ad_settings(**over), ldap=ldap)  # type: ignore[arg-type]
    await service.initialize()
    for name in names:
        assert await _signed_in_ad_user(service, store, name) is not None
    return service, ldap


@pytest.mark.parametrize("threshold", [2, 3, 5])
async def test_a_lasting_partial_outage_pages_once_and_a_full_answer_resolves_it_once(
    threshold: int,
) -> None:
    """``threshold`` passes that each answer ``bob`` and never ``alice`` page once, under the
    partial outage's own source; N-1 page nothing; one more pages nothing more; the first pass
    that answers ``alice`` resolves it, once, and the pass after it raises no second resolve.

    RED when: one answered probe ends the run again, so a partial outage never pages."""
    store = await MessageStore.open(":memory:")
    try:
        service, ldap = await _outage_service(store, ad_reconcile_outage_passes=threshold)
        sink = _InverseSink()
        ldap.unreachable = {"alice"}
        for n in range(1, threshold):
            plan = await _pass(service, sink)
            assert not plan.directory_outage and plan.aborted is None
            assert (_longest(service), plan.unreached) == (n, 1)
            assert not plan.partial_outage_page
        assert _pages(sink, _PARTIAL_OUTAGE_ALERT_SOURCE) == []  # the N-1 control
        assert await _rows(store) == []

        plan = await _pass(service, sink)
        assert plan.partial_outage_page and plan.partial_outage_probes == threshold
        [page] = _pages(sink, _PARTIAL_OUTAGE_ALERT_SOURCE)
        assert page["reason"] == "directory_partly_unavailable" and page["probed"] == 2
        assert (
            f"1 more signed-in account(s) unanswered on {threshold} probes running "
            "(1 of 2 unanswered this pass)"
        ) in page["detail"]
        assert len(page["detail"]) <= 200  # the store keeps 200 characters of a reason
        assert await _rows(store) == [
            {
                "reason": "directory_partly_unavailable",
                "accounts": 1,
                "probes": threshold,
                "unreached": 1,
                "asked": 2,
            }
        ]

        await _pass(service, sink)  # one more partial pass after firing
        assert len(_pages(sink, _PARTIAL_OUTAGE_ALERT_SOURCE)) == 1
        assert len(await _rows(store)) == 1

        ldap.unreachable = set()  # every probe is answered again
        plan = await _pass(service, sink)
        assert plan.partial_outage_clear and _longest(service) == 0
        assert not (await _pass(service, sink)).partial_outage_clear  # the flag was reset
        assert _clears(sink, _PARTIAL_OUTAGE_ALERT_SOURCE) == 1
        assert _events(sink, _OUTAGE_ALERT_SOURCE) == []  # not a whole outage at any point
    finally:
        await store.close()


async def test_a_fully_answered_pass_restarts_the_partial_run() -> None:
    """Two short partial runs with a fully answered pass between them never add up to a page,
    and with nothing paged nothing resolves.

    RED when: the count survives a pass that answered the account."""
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
            assert _longest(service) == 0 and not plan.partial_outage_clear
        assert _events(sink, _PARTIAL_OUTAGE_ALERT_SOURCE) == []
    finally:
        await store.close()


async def test_a_whole_pass_neither_feeds_nor_raises_the_partial_page() -> None:
    """Review round 3, findings 1 and 5. Passes alternate whole and partial, never answering
    ``alice``. Only the partial passes count toward her streak, so the page comes on the third
    partial pass, and never on a whole one; the whole outage never pages here either, since each
    partial pass ends its run, as before.

    RED when: a whole outage pass feeds a streak or raises the partial page."""
    store = await MessageStore.open(":memory:")
    try:
        service, ldap = await _outage_service(store)  # the default, 3
        sink = _InverseSink()
        plans = []
        for _ in range(3):
            for unreachable in (_BOTH, {"alice"}):
                ldap.unreachable = set(unreachable)
                plans.append(await _pass(service, sink))
        assert [p.directory_outage for p in plans] == [True, False] * 3
        assert [p.partial_outage_page for p in plans] == [False] * 5 + [True]
        assert [p.outage_passes for p in plans] == [1, 0] * 3
        assert len(_pages(sink, _PARTIAL_OUTAGE_ALERT_SOURCE)) == 1
        assert _pages(sink, _OUTAGE_ALERT_SOURCE) == []
    finally:
        await store.close()


async def test_a_partial_outage_that_turns_whole_pages_only_as_a_whole_outage() -> None:
    """Review round 3, finding 1. ``alice`` goes unanswered on two partial passes, then the whole
    directory goes. The whole passes do not page the partial outage, and her streak stays where it
    was; the whole outage pages once its own run is long enough.

    RED when: the first whole pass raises a partial page beside the whole one that follows."""
    store = await MessageStore.open(":memory:")
    try:
        service, ldap = await _outage_service(store)  # the default, 3
        sink = _InverseSink()
        ldap.unreachable = {"alice"}
        for _ in range(2):
            await _pass(service, sink)
        ldap.unreachable = set(_BOTH)
        plans = [await _pass(service, sink) for _ in range(3)]
        assert not any(p.partial_outage_page for p in plans)
        assert plans[-1].outage_page and _longest(service) == 2
        assert _events(sink, _PARTIAL_OUTAGE_ALERT_SOURCE) == []
        assert len(_pages(sink, _OUTAGE_ALERT_SOURCE)) == 1
    finally:
        await store.close()


async def test_after_a_whole_outage_one_blip_does_not_page_and_a_lasting_one_does() -> None:
    """Review round 3, finding 5. A whole outage pages as before and leaves no streak, so the
    first unanswered probe of ``alice`` after it pages nothing; her second does, at the threshold
    of 2. The partial pass resolves the whole page, and a fully answered pass resolves the
    partial one.

    RED when: the whole outage leaves every streak at the threshold, so the first blip pages."""
    store = await MessageStore.open(":memory:")
    try:
        service, ldap = await _outage_service(store, ad_reconcile_outage_passes=2)
        sink = _InverseSink()
        ldap.unreachable = set(_BOTH)
        for _ in range(3):
            plan = await _pass(service, sink)
            assert plan.directory_outage and not plan.partial_outage_page
        assert len(_pages(sink, _OUTAGE_ALERT_SOURCE)) == 1
        assert _longest(service) == 0

        ldap.unreachable = {"alice"}
        blip = await _pass(service, sink)
        assert blip.outage_clear and not blip.partial_outage_page
        assert _clears(sink, _OUTAGE_ALERT_SOURCE) == 1
        lasting = await _pass(service, sink)
        assert lasting.partial_outage_page and lasting.partial_outage_probes == 2

        ldap.unreachable = set()
        assert (await _pass(service, sink)).partial_outage_clear
        assert _clears(sink, _PARTIAL_OUTAGE_ALERT_SOURCE) == 1
    finally:
        await store.close()


async def test_a_second_account_entering_while_the_page_is_open_pages_again() -> None:
    """Review round 3, finding 2. ``alice`` pages; while she is still unanswered, ``bob`` is too,
    and pages once his own streak reaches the threshold. ``alice`` is not paged again.

    RED when: a second account reaching the threshold is lost behind the first page."""
    store = await MessageStore.open(":memory:")
    try:
        service, ldap = await _estate(store, "alice", "bob", "carol", ad_reconcile_outage_passes=2)
        sink = _InverseSink()
        ldap.unreachable = {"alice"}
        for _ in range(2):
            await _pass(service, sink)
        ldap.unreachable = {"alice", "bob"}
        first = await _pass(service, sink)
        second = await _pass(service, sink)
        assert not first.partial_outage_page
        assert second.partial_outage_page and len(second.partial_outage_entered) == 1
        assert second.partial_outage_probes == 2  # bob's streak, not alice's 4
        assert len(_pages(sink, _PARTIAL_OUTAGE_ALERT_SOURCE)) == 2
        assert [r["accounts"] for r in await _rows(store)] == [1, 1]
    finally:
        await store.close()


async def test_a_refused_row_leaves_the_page_to_the_next_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Review round 3, finding 11. The store refuses the partial outage's row, so that pass
    neither pages nor latches, and the next pass writes the row and pages: the page always
    matches a row.

    RED when: a refused row still pages, or latches the page so it never comes."""
    store = await MessageStore.open(":memory:")
    try:
        service, ldap = await _outage_service(store, ad_reconcile_outage_passes=2)
        sink = _InverseSink()
        ldap.unreachable = {"alice"}
        await _pass(service, sink)
        real = service._audit_reconciler_row

        async def refuse(action: str, **kw: Any) -> bool:
            if action == _ROW:
                return False
            return await real(action, **kw)

        monkeypatch.setattr(service, "_audit_reconciler_row", refuse)
        refused = await _pass(service, sink)
        assert not refused.partial_outage_page
        assert _pages(sink, _PARTIAL_OUTAGE_ALERT_SOURCE) == []
        monkeypatch.setattr(service, "_audit_reconciler_row", real)
        retried = await _pass(service, sink)
        assert retried.partial_outage_page and retried.partial_outage_probes == 3
        assert len(_pages(sink, _PARTIAL_OUTAGE_ALERT_SOURCE)) == 1
        assert len(await _rows(store)) == 1
    finally:
        await store.close()


async def test_a_group_search_refused_for_the_engines_bound_is_no_partial_outage() -> None:
    """The directory answered such a probe, and it pages on its own (vault BACKLOG #3696), so it
    feeds no streak and pages no partial outage however long it lasts.

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
            assert _longest(service) == 0
        assert _events(sink, _PARTIAL_OUTAGE_ALERT_SOURCE) == []
    finally:
        await store.close()


async def test_a_partial_threshold_pass_that_raises_pages_on_the_next_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The partial page is latched only once its pass's rows are written, so a pass that raises
    first leaves the next pass to page.

    RED when: the latch is set before the pass can raise, so the page never comes."""
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
        assert plan.partial_outage_page and plan.partial_outage_probes == 3
        assert len(_pages(sink, _PARTIAL_OUTAGE_ALERT_SOURCE)) == 1
        await _pass(service, sink)
        assert len(_pages(sink, _PARTIAL_OUTAGE_ALERT_SOURCE)) == 1
    finally:
        await store.close()


async def test_a_probe_budget_smaller_than_the_estate_cannot_reset_an_accounts_streak() -> None:
    """Review round 1. Three accounts and a budget of two probes a pass, so some passes do not
    probe ``alice`` at all, and answer every probe they send. Her streak survives them, grows on
    each pass that probes her, and pages once; those passes resolve nothing while she is
    unanswered.

    RED when: a pass that did not probe the unanswered account ends its streak."""
    store = await MessageStore.open(":memory:")
    try:
        service, ldap = await _estate(
            store,
            "alice",
            "bob",
            "carol",
            ad_reconcile_outage_passes=2,
            ad_session_recheck_max_users=2,
        )
        sink = _InverseSink()
        ldap.unreachable = {"alice"}
        alice = await store.get_user_by_username("alice")
        assert alice is not None
        plans = []
        for probed in (True, False, True, False, True, False):
            # The rotation sorts least recently probed first, so this puts alice first or last.
            service._reconcile_last_probed[alice.id] = 0.0 if probed else 1e18
            plans.append(await _pass(service, sink))
        assert all(p.asked == 2 and not p.directory_outage for p in plans)
        assert [p.unreached for p in plans] == [1, 0] * 3
        assert [p.partial_outage_page for p in plans] == [False, False, True, False, False, False]
        assert _clears(sink, _PARTIAL_OUTAGE_ALERT_SOURCE) == 0
    finally:
        await store.close()


async def test_one_off_failures_on_different_accounts_never_add_up() -> None:
    """Review round 1. Each pass leaves one probe unanswered, never the same account twice
    running, so no account's streak passes one and nothing pages.

    RED when: the run counts passes with any failure rather than one account's failures."""
    store = await MessageStore.open(":memory:")
    try:
        service, ldap = await _outage_service(store, ad_reconcile_outage_passes=2)
        sink = _InverseSink()
        for name in ("alice", "bob", "alice", "bob"):
            ldap.unreachable = {name}
            plan = await _pass(service, sink)
            assert plan.unreached == 1 and _longest(service) == 1
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
        assert [r["probes"] for r in await _rows(store)] == [2]
    finally:
        await store.close()


async def test_a_full_recovery_under_a_probe_budget_raises_no_partial_page() -> None:
    """Review round 2. Under a budget of one probe a pass, a whole outage pages as a whole outage
    and feeds no streak. When the directory comes back, no pass pages a partial outage.

    RED when: a whole outage leaves streaks that page on a healthy pass."""
    store = await MessageStore.open(":memory:")
    try:
        service, ldap = await _outage_service(
            store, ad_reconcile_outage_passes=2, ad_session_recheck_max_users=1
        )
        sink = _InverseSink()
        ldap.unreachable = set(_BOTH)
        for _ in range(4):
            assert (await _pass(service, sink)).directory_outage
        assert len(_pages(sink, _OUTAGE_ALERT_SOURCE)) == 1
        ldap.unreachable = set()
        back = await _pass(service, sink)
        assert back.outage_clear and not back.partial_outage_page
        await _pass(service, sink)
        assert _longest(service) == 0
        assert _events(sink, _PARTIAL_OUTAGE_ALERT_SOURCE) == []
        assert await _rows(store) == []
    finally:
        await store.close()
