# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A lasting PARTIAL directory outage pages (BACKLOG #3709 step 1, #4772 item 6).

Before this, one answered probe ended the outage run, so a directory that answered for some
accounts and never for the rest paged nobody. Each account now has a streak of probes the
directory left unanswered, counted on every pass that probes it, and a pass that reaches the
directory pages each account entering that state under its own source. Each test drives the
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
_ALICE = f"{_PARTIAL_OUTAGE_ALERT_SOURCE}:alice"
_BOB = f"{_PARTIAL_OUTAGE_ALERT_SOURCE}:bob"


def _events(sink: _InverseSink, source: str) -> list[tuple[str, dict[str, Any]]]:
    return [(kind, fields) for kind, name, fields in sink.events if name == source]


def _pages(sink: _InverseSink, source: str) -> list[dict[str, Any]]:
    return [fields for kind, fields in _events(sink, source) if kind == "ad_reconcile_aborted"]


def _partial_events(sink: _InverseSink) -> list[tuple[str, str]]:
    """Every event under the partial outage's source or any account's, as ``(kind, source)``."""
    return [
        (kind, name)
        for kind, name, _fields in sink.events
        if name == _PARTIAL_OUTAGE_ALERT_SOURCE
        or name.startswith(f"{_PARTIAL_OUTAGE_ALERT_SOURCE}:")
    ]


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
async def test_a_lasting_partial_outage_pages_once_under_the_accounts_own_source(
    threshold: int,
) -> None:
    """``threshold`` passes that each answer ``bob`` and never ``alice`` page once, under her own
    source; N-1 page nothing; one more pages nothing more. Answering her raises no inverse, and a
    later run of the same length pages her again.

    RED when: one answered probe ends the run again, so a partial outage never pages."""
    store = await MessageStore.open(":memory:")
    try:
        service, ldap = await _outage_service(store, ad_reconcile_outage_passes=threshold)
        sink = _InverseSink()
        ldap.unreachable = {"alice"}
        for n in range(1, threshold):
            plan = await _pass(service, sink)
            assert not plan.directory_outage and plan.aborted is None
            assert (_longest(service), plan.unreached_probes) == (n, 1)
            assert not plan.partial_outage_page
        assert _partial_events(sink) == []  # the N-1 control
        assert await _rows(store) == []

        plan = await _pass(service, sink)
        assert plan.partial_outage_page and plan.partial_outage_probes == threshold
        assert not plan.partial_outage_rollup
        [page] = _pages(sink, _ALICE)
        assert page["reason"] == "directory_partly_unavailable" and page["probed"] == 2
        assert f"the directory left {threshold} of its probes running unanswered" in page["detail"]
        assert len(page["detail"]) <= 200  # the store keeps 200 characters of a reason
        assert await _rows(store) == [
            {
                "reason": "directory_partly_unavailable",
                "accounts": 1,
                "probes": threshold,
                "rollup": False,
                "asked": 2,
            }
        ]

        await _pass(service, sink)  # one more partial pass after firing
        assert len(_pages(sink, _ALICE)) == 1
        assert len(await _rows(store)) == 1

        ldap.unreachable = set()  # every probe is answered again
        await _pass(service, sink)
        assert _longest(service) == 0
        assert [kind for kind, _ in _partial_events(sink)] == ["ad_reconcile_aborted"]  # no inverse
        assert _events(sink, _OUTAGE_ALERT_SOURCE) == []  # not a whole outage at any point

        ldap.unreachable = {"alice"}  # re-armed by the answer
        for _ in range(threshold):
            await _pass(service, sink)
        assert len(_pages(sink, _ALICE)) == 2
    finally:
        await store.close()


async def test_a_fully_answered_pass_restarts_the_partial_run() -> None:
    """Two short partial runs with a fully answered pass between them never add up to a page.

    RED when: the count survives a pass that answered the account."""
    store = await MessageStore.open(":memory:")
    try:
        service, ldap = await _outage_service(store)  # the default, 3
        sink = _InverseSink()
        for _run in range(2):
            ldap.unreachable = {"alice"}
            for _ in range(2):
                assert (await _pass(service, sink)).unreached_probes == 1
            ldap.unreachable = set()
            await _pass(service, sink)
            assert _longest(service) == 0
        assert _partial_events(sink) == []
    finally:
        await store.close()


async def test_a_whole_pass_feeds_the_streak_and_never_raises_the_partial_page() -> None:
    """Review pass 1029f-r1, finding 7. Passes alternate whole and partial, never answering
    ``alice``. Every pass counts toward her streak, so it reaches the threshold of 3 on the third
    pass, a whole one, which does not page; the partial pass after it does. The whole outage
    never pages, since each partial pass ends its run.

    RED when: a whole pass raises the partial page, or feeds no streak."""
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
        assert [p.partial_outage_page for p in plans] == [False] * 3 + [True, False, False]
        assert [p.outage_passes for p in plans] == [1, 0] * 3
        assert len(_pages(sink, _ALICE)) == 1
        assert _pages(sink, _OUTAGE_ALERT_SOURCE) == []
    finally:
        await store.close()


async def test_a_partial_outage_that_turns_whole_pages_only_as_a_whole_outage() -> None:
    """``alice`` goes unanswered on two partial passes, then the whole directory goes. The whole
    passes do not page the partial outage; the whole outage pages once its own run is long enough.

    RED when: a whole pass raises a partial page beside the whole one."""
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
        assert plans[-1].outage_page and _longest(service) == 5
        assert _partial_events(sink) == []
        assert len(_pages(sink, _OUTAGE_ALERT_SOURCE)) == 1
    finally:
        await store.close()


async def test_the_end_of_a_whole_run_that_paged_restarts_every_streak() -> None:
    """A whole outage pages as before and feeds every streak; the pass that ends it restarts
    them, since its page covered them, so the first unanswered probe of ``alice`` after it pages
    nothing and her second does, at the threshold of 2.

    RED when: the streaks a paged whole outage fed page as a partial outage once it ends."""
    store = await MessageStore.open(":memory:")
    try:
        service, ldap = await _outage_service(store, ad_reconcile_outage_passes=2)
        sink = _InverseSink()
        ldap.unreachable = set(_BOTH)
        for _ in range(3):
            plan = await _pass(service, sink)
            assert plan.directory_outage and not plan.partial_outage_page
        assert len(_pages(sink, _OUTAGE_ALERT_SOURCE)) == 1
        assert _longest(service) == 3

        ldap.unreachable = {"alice"}
        blip = await _pass(service, sink)
        assert blip.outage_clear and not blip.partial_outage_page
        assert _longest(service) == 1
        lasting = await _pass(service, sink)
        assert lasting.partial_outage_page and lasting.partial_outage_probes == 2
        assert len(_pages(sink, _ALICE)) == 1
    finally:
        await store.close()


async def test_a_second_account_pages_under_its_own_source() -> None:
    """Review pass 1029f-r1, finding 8. ``alice`` pages; while she is still unanswered, ``bob``
    is too, and pages under his own source once his streak reaches the threshold, so the
    notifier's cooldown on her page cannot hold his. ``alice`` is not paged again.

    RED when: every account shares one source, so a second account's page is throttled."""
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
        assert len(_pages(sink, _ALICE)) == 1 and len(_pages(sink, _BOB)) == 1
        assert "left 2 of its probes" in _pages(sink, _BOB)[0]["detail"]
        assert [r["accounts"] for r in await _rows(store)] == [1, 1]
    finally:
        await store.close()


async def test_many_accounts_entering_at_once_page_once_under_the_bare_source() -> None:
    """Six of seven accounts go unanswered together, which is more than the rollup bound of five,
    so one page under the bare source covers them and names none.

    RED when: a dead domain controller behind many accounts opens one instance per account."""
    store = await MessageStore.open(":memory:")
    try:
        names = ("alice", "bob", "carol", "dave", "erin", "frank", "grace")
        service, ldap = await _estate(store, *names, ad_reconcile_outage_passes=2)
        sink = _InverseSink()
        ldap.unreachable = set(names[:6])
        for _ in range(2):
            plan = await _pass(service, sink)
        assert plan.partial_outage_rollup and len(plan.partial_outage_entered) == 6
        assert _partial_events(sink) == [("ad_reconcile_aborted", _PARTIAL_OUTAGE_ALERT_SOURCE)]
        [page] = _pages(sink, _PARTIAL_OUTAGE_ALERT_SOURCE)
        assert page["detail"].startswith("6 more accounts' sessions are not reconciled")
        assert len(page["detail"]) <= 200
        assert not any(name in page["detail"] for name in names)
        assert [r["rollup"] for r in await _rows(store)] == [True]
    finally:
        await store.close()


async def test_a_refused_row_leaves_the_page_to_the_next_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The store refuses the partial outage's row, so that pass neither pages nor latches, and
    the next pass writes the row and pages: the page always matches a row.

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
        assert _partial_events(sink) == []
        monkeypatch.setattr(service, "_audit_reconciler_row", real)
        retried = await _pass(service, sink)
        assert retried.partial_outage_page and retried.partial_outage_probes == 3
        assert len(_pages(sink, _ALICE)) == 1
        assert len(await _rows(store)) == 1
    finally:
        await store.close()


async def test_a_group_search_refused_for_the_engines_bound_is_no_partial_outage() -> None:
    """The directory answered such a probe, and it pages on its own (vault BACKLOG #3696), so it
    feeds no streak and pages no partial outage however long it lasts.

    RED when: a standing paging refusal also opens a partial outage."""
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
            assert plan.unavailable == 1 and plan.unreached_probes == 0
            assert _longest(service) == 0
        assert _partial_events(sink) == []
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
        assert len(_pages(sink, _ALICE)) == 1
        await _pass(service, sink)
        assert len(_pages(sink, _ALICE)) == 1
    finally:
        await store.close()


async def test_a_probe_budget_smaller_than_the_estate_cannot_reset_an_accounts_streak() -> None:
    """Three accounts and a budget of two probes a pass, so some passes do not probe ``alice`` at
    all, and answer every probe they send. Her streak survives them, grows on each pass that
    probes her, and pages once.

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
            # The rotation sorts least recently probed first, a never-probed account at 0.0 and a
            # tie by id, so this puts alice first or last whatever the ids.
            service._reconcile_last_probed[alice.id] = -1.0 if probed else 1e18
            plans.append(await _pass(service, sink))
        assert all(p.asked == 2 and not p.directory_outage for p in plans)
        assert [p.unreached_probes for p in plans] == [1, 0] * 3
        assert [p.partial_outage_page for p in plans] == [False, False, True, False, False, False]
        assert len(_pages(sink, _ALICE)) == 1
    finally:
        await store.close()


async def test_a_sample_that_holds_only_the_unanswered_account_still_pages() -> None:
    """Review pass 1029f-r1, finding 7. At a budget of one probe a pass, ``alice``'s own passes
    each read as a whole outage, and ``bob``'s answers end that run, so the whole outage never
    pages. Her streak still grows on her passes, and the next pass that reaches the directory
    pages her, whichever account the rotation took first.

    RED when: a whole-looking sampled pass feeds no streak, so neither page ever comes."""
    store = await MessageStore.open(":memory:")
    try:
        service, ldap = await _outage_service(
            store, ad_reconcile_outage_passes=2, ad_session_recheck_max_users=1
        )
        sink = _InverseSink()
        ldap.unreachable = {"alice"}
        plans = [await _pass(service, sink) for _ in range(5)]
        assert all(p.asked == 1 for p in plans)
        assert not any(p.outage_page for p in plans)
        assert sum(p.partial_outage_page for p in plans) == 1
        assert len(_pages(sink, _ALICE)) == 1
        assert _pages(sink, _OUTAGE_ALERT_SOURCE) == []
    finally:
        await store.close()


async def test_a_fault_leaves_the_streak_as_it_stands() -> None:
    """Review pass 1029f-r1, finding 5. ``alice``'s probes alternate unanswered and faulted while
    ``bob`` is answered. A fault says nothing about reach, so it neither ends nor feeds her
    streak, and her second unanswered probe pages at the threshold of 2.

    RED when: a fault ends the streak as an answer would, so the page never comes."""
    store = await MessageStore.open(":memory:")
    try:
        service, ldap = await _outage_service(store, ad_reconcile_outage_passes=2)
        sink = _InverseSink()
        ldap.unreachable = {"alice"}
        await _pass(service, sink)
        ldap.unreachable = set()
        ldap.broken = {"alice": ValueError("synthetic: unreadable entry")}
        faulted = await _pass(service, sink)
        assert faulted.faulted and _longest(service) == 1 and not faulted.partial_outage_page
        ldap.broken = {}
        ldap.unreachable = {"alice"}
        assert (await _pass(service, sink)).partial_outage_page
        assert len(_pages(sink, _ALICE)) == 1
    finally:
        await store.close()


async def test_one_off_failures_on_different_accounts_never_add_up() -> None:
    """Each pass leaves one probe unanswered, never the same account twice running, so no
    account's streak passes one and nothing pages.

    RED when: the run counts passes with any failure rather than one account's failures."""
    store = await MessageStore.open(":memory:")
    try:
        service, ldap = await _outage_service(store, ad_reconcile_outage_passes=2)
        sink = _InverseSink()
        for name in ("alice", "bob", "alice", "bob"):
            ldap.unreachable = {name}
            plan = await _pass(service, sink)
            assert plan.unreached_probes == 1 and _longest(service) == 1
        assert _partial_events(sink) == []
    finally:
        await store.close()


async def test_a_referral_beside_the_unanswered_account_still_pages() -> None:
    """``bob`` is referred on every pass, so each pass aborts as a referral and judges nothing.
    The directory still answered ``bob`` and never ``alice``, so the aborted path pages the
    partial outage and writes its row.

    RED when: the aborted path drops the partial page or its row."""
    store = await MessageStore.open(":memory:")
    try:
        service, ldap = await _outage_service(store, ad_reconcile_outage_passes=2)
        sink = _InverseSink()
        ldap.unreachable = {"alice"}
        ldap.referring = {"bob"}
        first = await _pass(service, sink)
        second = await _pass(service, sink)
        assert first.aborted is not None and first.judged_nothing
        assert not first.partial_outage_page and second.partial_outage_page
        assert len(_pages(sink, _ALICE)) == 1
        assert [r["probes"] for r in await _rows(store)] == [2]
    finally:
        await store.close()


async def test_a_pass_of_failures_and_faults_pages_no_partial_outage() -> None:
    """Review pass 1029f-r1, finding 4. ``bob``'s probe faults on every pass and ``alice`` is
    unanswered, so every probe failed or faulted: the pass did not show the directory reached,
    so it pages as a probe fault and never as a partial outage, though ``alice``'s streak grows.
    The first pass that reaches the directory pages her.

    RED when: a total outage with one faulting probe is paged as a partial one."""
    store = await MessageStore.open(":memory:")
    try:
        service, ldap = await _outage_service(store, ad_reconcile_outage_passes=2)
        sink = _InverseSink()
        ldap.unreachable = {"alice"}
        ldap.broken = {"bob": ValueError("synthetic: unreadable entry")}
        plans = [await _pass(service, sink) for _ in range(3)]
        assert all(p.probe_fault and not p.partial_outage_page for p in plans)
        assert _longest(service) == 3 and _partial_events(sink) == []
        ldap.broken = {}
        reached = await _pass(service, sink)
        assert reached.partial_outage_page and reached.partial_outage_probes == 4
        assert len(_pages(sink, _ALICE)) == 1
    finally:
        await store.close()


async def test_a_full_recovery_under_a_probe_budget_raises_no_partial_page() -> None:
    """Under a budget of one probe a pass, a whole outage pages as a whole outage. When the
    directory comes back, the pass that ends that run restarts every streak it fed, so no pass
    pages a partial outage.

    RED when: the streaks a whole outage fed page on a healthy pass."""
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
        assert _partial_events(sink) == []
        assert await _rows(store) == []
    finally:
        await store.close()
