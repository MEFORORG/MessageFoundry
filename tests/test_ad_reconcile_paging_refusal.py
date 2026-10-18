# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #3696, the Lander's send-back on PR 2431: a revoke that cannot run must page.

A group search refused for the engine's own bound, past ``[auth].ad_group_search_deadline`` or
past the entry cap, reads that account as UNAVAILABLE, so the reconciler never revokes it while it
lasts. Unlike an outage it recurs on every pass. So it pages through the AlertSink, once per
account as it enters that state, and again only after the account reads otherwise. A plain outage
still pages nobody. All directory data here is synthetic.
"""

from __future__ import annotations

import pytest

from messagefoundry.api.app import _alert_reconcile_plan
from messagefoundry.auth import reconcile
from messagefoundry.auth.ldap import (
    PAGING_DEADLINE_SPENT,
    PAGING_TOO_MANY_ENTRIES,
    PAGING_TOO_MANY_PAGES,
    DirectoryProbe,
    LdapUnansweredError,
)
from messagefoundry.auth.service import AuthService
from messagefoundry.store.store import MessageStore
from tests.test_ad_session_reconcile import _ad_settings, _FakeLdap, _principal, _signed_in_ad_user
from tests.test_approval_requester_recheck import _Sink

_SOURCE = "directory-reconciler-paging:"


class _BoundedLdap(_FakeLdap):
    """The reconcile double, plus accounts whose group search the engine refuses for its bound
    (``bounded``, username -> the refusal's ``code_name``) or for a result code (``unanswered``)."""

    def __init__(self, *names: str) -> None:
        super().__init__({name: _principal(name) for name in names})
        self.bounded: dict[str, str] = {}
        self.unanswered: set[str] = set()

    def probe_principal(self, username: str, *, object_id: str | None = None) -> DirectoryProbe:
        if username in self.bounded:
            raise LdapUnansweredError(
                "synthetic: the group search was refused", code_name=self.bounded[username]
            )
        if username in self.unanswered:
            raise LdapUnansweredError("synthetic: result code 51 (busy)", code=51, code_name="busy")
        return super().probe_principal(username, object_id=object_id)


async def _service(store: MessageStore, ldap: _BoundedLdap) -> tuple[AuthService, list[str]]:
    service = AuthService(store, _ad_settings(), ldap=ldap)  # type: ignore[arg-type]
    await service.initialize()
    tokens = [await _signed_in_ad_user(service, store, name) for name in ldap.present]
    assert all(tokens)
    return service, [t for t in tokens if t is not None]


async def _pages(service: AuthService) -> tuple[reconcile.ReconcilePlan, list[tuple[str, str]]]:
    """One pass, and the ``(source, reason)`` of each paging page the lifespan task raised for it."""
    plan = await service.reconcile_directory_sessions()
    sink = _Sink()
    _alert_reconcile_plan(plan, service, sink)
    pages = [
        (name, fields["reason"])
        for kind, name, fields in sink.events
        if kind == "ad_reconcile_aborted" and name.startswith(_SOURCE)
    ]
    return plan, pages


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
    """The page fires as the account enters the state, not on the next pass, and again after the
    account reads normally and then enters it once more. Alone, the pass is outage-shaped
    (``directory_unavailable``), which pages nobody for the outage, and still pages for this. The
    account is never revoked meanwhile: the refusal still reads UNAVAILABLE."""
    store = await MessageStore.open(":memory:")
    try:
        ldap = _BoundedLdap("jdoe") if alone else _BoundedLdap("jdoe", "asmith")
        service, tokens = await _service(store, ldap)
        ldap.bounded["jdoe"] = code_name

        plan, pages = await _pages(service)
        assert plan.directory_outage is alone
        assert plan.paging_refused == (("jdoe", cause),)
        assert pages == [(f"{_SOURCE}jdoe", cause)]

        plan, pages = await _pages(service)
        assert (plan.paging_refused, pages) == ((), []), "paged again on the next pass"

        del ldap.bounded["jdoe"]  # the account reads normally again
        assert (await _pages(service))[1] == []
        ldap.bounded["jdoe"] = code_name
        assert (await _pages(service))[1] == [(f"{_SOURCE}jdoe", cause)], "did not re-arm"

        for token in tokens:
            assert await service.identity_for_token(token) is not None
    finally:
        await store.close()


async def test_a_change_of_bound_pages_again_and_the_text_carries_only_the_account() -> None:
    """A deadline refusal that becomes a cap refusal is a state change. The detail names the
    account and the setting, and nothing the directory sent."""
    store = await MessageStore.open(":memory:")
    try:
        ldap = _BoundedLdap("jdoe", "asmith")
        service, _tokens = await _service(store, ldap)
        ldap.bounded["jdoe"] = PAGING_DEADLINE_SPENT
        await _pages(service)
        ldap.bounded["jdoe"] = PAGING_TOO_MANY_ENTRIES
        plan = await service.reconcile_directory_sessions()
        sink = _Sink()
        _alert_reconcile_plan(plan, service, sink)
        [(kind, name, fields)] = [e for e in sink.events if e[1].startswith(_SOURCE)]
        assert (kind, name, fields["reason"]) == (
            "ad_reconcile_aborted",
            f"{_SOURCE}jdoe",
            reconcile.PAGING_CAP,
        )
        assert fields["detail"].startswith("jdoe: the directory group search returned more groups")
        assert "synthetic" not in fields["detail"]
    finally:
        await store.close()


@pytest.mark.parametrize("alone", [False, True], ids=["beside-an-answer", "outage-shaped-pass"])
@pytest.mark.parametrize("how", ["unreachable", "unanswered"])
async def test_a_plain_outage_raises_no_paging_page(alone: bool, how: str) -> None:
    """A directory that is down, or answers with a code that is not an answer, keeps its existing
    behaviour: UNAVAILABLE, no page of this kind. Nor does an outage re-arm a latched account, so
    the paging page does not fire again when the outage passes and the bound still refuses."""
    store = await MessageStore.open(":memory:")
    try:
        ldap = _BoundedLdap("jdoe") if alone else _BoundedLdap("jdoe", "asmith")
        service, _tokens = await _service(store, ldap)
        (ldap.unreachable if how == "unreachable" else ldap.unanswered).add("jdoe")
        plan, pages = await _pages(service)
        assert plan.directory_outage is alone
        assert (plan.unavailable, plan.paging_refused, pages) == (1, (), [])

        ldap.unreachable.clear()
        ldap.unanswered.clear()
        ldap.bounded["jdoe"] = PAGING_DEADLINE_SPENT
        assert len((await _pages(service))[1]) == 1
        (ldap.unreachable if how == "unreachable" else ldap.unanswered).add("jdoe")
        assert (await _pages(service))[1] == []
        ldap.unreachable.clear()
        ldap.unanswered.clear()
        assert (await _pages(service))[1] == [], "an outage re-armed the latch"
    finally:
        await store.close()
