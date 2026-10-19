# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #3696, the Lander's send-back on PR 2431: a revoke that cannot run must page.

A group search refused for the engine's own bound, past ``[auth].ad_group_search_deadline`` or
past the entry cap, reads that account as UNAVAILABLE, so the reconciler never revokes it while it
lasts. Unlike an outage it recurs on every pass. So it pages through the AlertSink, and audits
``auth.ad_reconcile_paging_refused``, once per account as it enters that state, and again only
after the account reads otherwise. A plain outage still pages nobody. All directory data here is
synthetic.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from messagefoundry.api.app import _alert_reconcile_plan
from messagefoundry.auth import reconcile
from messagefoundry.auth.ldap import (
    PAGING_DEADLINE_SPENT,
    PAGING_TOO_MANY_ENTRIES,
    PAGING_TOO_MANY_PAGES,
    LdapError,
    LdapReferralError,
    LdapUnansweredError,
)
from messagefoundry.auth.service import AuthService
from messagefoundry.store.store import MessageStore
from tests.test_ad_session_reconcile import _ad_settings, _FakeLdap, _principal, _signed_in_ad_user
from tests.test_approval_requester_recheck import _Sink

_SOURCE = "directory-reconciler-paging:"
_ACTION = "auth.ad_reconcile_paging_refused"


def _bounded(code_name: str) -> LdapUnansweredError:
    """What ``_search_paged`` raises for a search refused for its bound."""
    return LdapUnansweredError("synthetic: the group search was refused", code_name=code_name)


#: The two plain outages: a directory that is down, and one that answers with a code that is not
#: an answer. Neither names a bound.
_OUTAGES: dict[str, LdapError] = {
    "unreachable": LdapError("synthetic: LDAP socket closed"),
    "unanswered": LdapUnansweredError(
        "synthetic: result code 51 (busy)", code=51, code_name="busy"
    ),
}


async def _service(store: MessageStore, *names: str) -> tuple[AuthService, _FakeLdap, list[str]]:
    ldap = _FakeLdap({name: _principal(name) for name in names})
    service = AuthService(store, _ad_settings(), ldap=ldap)  # type: ignore[arg-type]
    await service.initialize()
    tokens = [await _signed_in_ad_user(service, store, name) for name in names]
    return service, ldap, [t for t in tokens if t is not None]


async def _pages(
    service: AuthService,
) -> tuple[reconcile.ReconcilePlan, list[tuple[str, dict[str, Any]]]]:
    """One pass, and the ``(source, fields)`` of each paging page the lifespan task raised."""
    plan = await service.reconcile_directory_sessions()
    sink = _Sink()
    _alert_reconcile_plan(plan, service, sink)
    pages = [
        (name, fields)
        for kind, name, fields in sink.events
        if kind == "ad_reconcile_aborted" and name.startswith(_SOURCE)
    ]
    return plan, pages


async def _rows(store: MessageStore) -> list[tuple[str, str]]:
    """``(actor, reason)`` of each paging refusal's audit row."""
    rows = [dict(r) for r in await store.list_audit(action=_ACTION)]
    return [(str(r["actor"]), json.loads(str(r["detail"]))["reason"]) for r in rows]


@pytest.mark.parametrize(
    ("code_name", "cause"),
    [
        (PAGING_DEADLINE_SPENT, reconcile.PAGING_DEADLINE),
        (PAGING_TOO_MANY_ENTRIES, reconcile.PAGING_CAP),
        (PAGING_TOO_MANY_PAGES, reconcile.PAGING_CAP),
    ],
    ids=["deadline", "entry-cap", "page-backstop"],
)
@pytest.mark.parametrize("alone", [False, True], ids=["beside-an-answer", "outage-shaped-pass"])
async def test_a_bounded_group_search_pages_once_per_state_change(
    code_name: str, cause: str, alone: bool
) -> None:
    """The page and its audit row come as the account enters the state, not on the next pass, and
    again after the account reads normally and then enters it once more. Alone, the pass is
    outage-shaped (``directory_unavailable``), which pages nobody for the outage, and still pages
    for this. The enabled account's sessions are not revoked meanwhile: it still reads
    UNAVAILABLE."""
    store = await MessageStore.open(":memory:")
    try:
        names = ("jdoe",) if alone else ("jdoe", "asmith")
        service, ldap, tokens = await _service(store, *names)
        ldap.broken["jdoe"] = _bounded(code_name)

        plan, pages = await _pages(service)
        assert plan.directory_outage is alone
        assert [(name, why) for _uid, name, why in plan.paging_refused] == [("jdoe", cause)]
        assert [(name, fields["reason"]) for name, fields in pages] == [(f"{_SOURCE}jdoe", cause)]
        assert await _rows(store) == [("jdoe", cause)]

        plan, pages = await _pages(service)
        assert (plan.paging_refused, pages) == ((), []), "paged again on the next pass"
        assert len(await _rows(store)) == 1, "audited again on the next pass"

        del ldap.broken["jdoe"]  # the account reads normally again
        assert (await _pages(service))[1] == []
        ldap.broken["jdoe"] = _bounded(code_name)
        assert len((await _pages(service))[1]) == 1, "did not re-arm"
        assert await _rows(store) == [("jdoe", cause), ("jdoe", cause)]

        for token in tokens:
            assert await service.identity_for_token(token) is not None
    finally:
        await store.close()


async def test_a_change_of_bound_is_not_a_new_state_and_the_text_names_no_directory_value() -> None:
    """An account that alternates between the deadline and the cap stays in one state, so it
    pages once. The detail names the setting, not the account, which is in the source only, and
    nothing the directory sent."""
    store = await MessageStore.open(":memory:")
    try:
        service, ldap, _tokens = await _service(store, "jdoe", "asmith")
        ldap.broken["jdoe"] = _bounded(PAGING_DEADLINE_SPENT)
        [(name, fields)] = (await _pages(service))[1]
        assert (name, fields["reason"]) == (f"{_SOURCE}jdoe", reconcile.PAGING_DEADLINE)
        assert "ran past [auth].ad_group_search_deadline" in fields["detail"]
        assert "synthetic" not in fields["detail"] and "jdoe" not in fields["detail"]
        ldap.broken["jdoe"] = _bounded(PAGING_TOO_MANY_ENTRIES)
        assert (await _pages(service))[1] == []
        ldap.broken["jdoe"] = _bounded(PAGING_DEADLINE_SPENT)
        assert (await _pages(service))[1] == []
    finally:
        await store.close()


@pytest.mark.parametrize(
    "unjudged",
    [LdapReferralError("synthetic: referred"), KeyError("synthetic")],
    ids=["referral", "probe-fault"],
)
async def test_a_referral_or_fault_does_not_re_arm(unjudged: Exception) -> None:
    """A referral or a probe fault judged nothing about the account, so, like an outage, it says
    nothing about the bound: the account stays latched and does not page again. Its own detail is
    not a bound either, so it raises no paging page of its own."""
    store = await MessageStore.open(":memory:")
    try:
        service, ldap, _tokens = await _service(store, "jdoe", "asmith")
        ldap.broken["jdoe"] = _bounded(PAGING_TOO_MANY_ENTRIES)
        assert len((await _pages(service))[1]) == 1
        ldap.broken["jdoe"] = unjudged
        assert (await _pages(service))[1] == [], "a referral or fault paged as a paging refusal"
        ldap.broken["jdoe"] = _bounded(PAGING_TOO_MANY_ENTRIES)
        assert (await _pages(service))[1] == [], "an unjudged answer re-armed the latch"
    finally:
        await store.close()


async def test_a_pass_that_raises_before_the_row_pages_on_the_next_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The latch is set only once the entry is recorded. A pass that raises before then leaves
    the account to enter again on the next pass, so its page and row are delayed, never lost."""
    store = await MessageStore.open(":memory:")
    try:
        service, ldap, _tokens = await _service(store, "jdoe", "asmith")
        ldap.broken["jdoe"] = _bounded(PAGING_DEADLINE_SPENT)
        calls = 0
        real = service._record_reconcile_fault

        async def raise_once(plan: reconcile.ReconcilePlan) -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise RuntimeError("synthetic: the pass fails part-way")
            await real(plan)

        monkeypatch.setattr(service, "_record_reconcile_fault", raise_once)
        with pytest.raises(RuntimeError, match="part-way"):
            await service.reconcile_directory_sessions()
        assert await _rows(store) == []
        assert len((await _pages(service))[1]) == 1, "the entry was lost with the failed pass"
        assert await _rows(store) == [("jdoe", reconcile.PAGING_DEADLINE)]
    finally:
        await store.close()


@pytest.mark.parametrize("alone", [False, True], ids=["beside-an-answer", "outage-shaped-pass"])
@pytest.mark.parametrize("how", sorted(_OUTAGES))
async def test_a_plain_outage_raises_no_paging_page(alone: bool, how: str) -> None:
    """A directory that is down, or answers with a code that is not an answer, keeps its existing
    behaviour: UNAVAILABLE, no page or row of this kind. Nor does an outage re-arm a latched
    account, so nothing pages again when the outage passes and the bound still refuses."""
    store = await MessageStore.open(":memory:")
    try:
        names = ("jdoe",) if alone else ("jdoe", "asmith")
        service, ldap, _tokens = await _service(store, *names)
        ldap.broken["jdoe"] = _OUTAGES[how]
        plan, pages = await _pages(service)
        assert plan.directory_outage is alone
        assert (plan.unavailable, plan.paging_refused, pages) == (1, (), [])
        assert await _rows(store) == []

        ldap.broken["jdoe"] = _bounded(PAGING_DEADLINE_SPENT)
        assert len((await _pages(service))[1]) == 1
        ldap.broken["jdoe"] = _OUTAGES[how]
        assert (await _pages(service))[1] == []
        ldap.broken["jdoe"] = _bounded(PAGING_DEADLINE_SPENT)
        assert (await _pages(service))[1] == [], "an outage re-armed the latch"
    finally:
        await store.close()
