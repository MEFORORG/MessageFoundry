# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A reconcile pass that meets an AD map Vault transit cannot verify pages, audits and ends the
sessions that map governs (owner ruling 2026-11-10 on ADR 0217, "Hold, build AD-map piece").
Synthetic data only.

Before, an Unverifiable or Outage answer on a map raised out of the pass, the reconcile loop logged
it, and the pass revoked nothing. SQLite runs a whole pass on a real store with the map's seal check
replaced; Postgres and SQL Server run the map reader over their twins with the reads replaced,
since a live server is not needed to see what the reader takes and where it pages.
"""

from __future__ import annotations

import importlib
import json
from typing import Any

import pytest

from messagefoundry.auth import service as service_module
from messagefoundry.auth.service import AuthService
from messagefoundry.store.row_seal import (
    SealPager,
    TransitSealUnavailableError,
    TransitSealUnverifiableError,
)
from messagefoundry.store.store import (
    AD_ROLE_MAP,
    AD_SCOPE_MAP,
    AdMap,
    MessageStore,
    ad_map_seal_ok_async,
)
from tests.test_ad_session_reconcile import _ad_settings, _FakeLdap, _principal, _signed_in_ad_user

_ADMINS = "cn=mf-admins,dc=test,dc=invalid"
_CHANNELS = "cn=mf-ib-a,dc=test,dc=invalid"


def _refusal(kind: str) -> Exception:
    if kind == "outage":
        return TransitSealUnavailableError()
    return TransitSealUnverifiableError("adset", 5, 1)


def _refuse(monkeypatch: pytest.MonkeyPatch, name: str, kind: str) -> None:
    """Make the seal check of map ``name`` answer as Vault transit would: Unverifiable or Outage."""
    real = ad_map_seal_ok_async

    async def check(sealer: Any, current: AdMap) -> bool:
        if current.name == name:
            raise _refusal(kind)
        return await real(sealer, current)

    monkeypatch.setattr(service_module, "ad_map_seal_ok_async", check)


async def _audits(store: MessageStore, action: str) -> list[dict[str, Any]]:
    return [json.loads(row["detail"]) for row in await store.list_audit(action=action)]


_EXPECT = {
    "unverifiable": (
        "integrity.authority_seal_unverifiable",
        "directory_map_unverifiable",
        "authority-seal-transit-unverifiable:adset:",
    ),
    "outage": (
        "integrity.authority_seal_unavailable",
        "seal_unavailable",
        "authority-seal-transit",
    ),
}


async def _estate(
    names: tuple[str, ...], *groups: str
) -> tuple[MessageStore, _FakeLdap, AuthService, dict[str, str], list[str]]:
    """Accounts signed in holding ``groups`` under a role map giving the admin group Administrator
    and a scope map giving the channel group IB_A, written through the store so no session ends."""
    store = await MessageStore.open(":memory:")
    pages: list[str] = []
    store.seal_pager().arm(lambda subject, reason: pages.append(f"{subject}|{reason}"))
    try:
        ldap = _FakeLdap({n: _principal(n, *groups) for n in names})
        service = AuthService(store, _ad_settings(), ldap=ldap)  # type: ignore[arg-type]
        await service.initialize()  # seeds the built-in roles the map names
        await store.set_ad_group_role_map([(_ADMINS, "administrator")])
        await store.set_ad_group_scope_map([(_CHANNELS, "IB_A")])
        tokens = {}
        for name in names:
            token = await _signed_in_ad_user(service, store, name)
            assert token is not None
            tokens[name] = token
    except BaseException:
        await store.close()
        raise
    return store, ldap, service, tokens, pages


@pytest.mark.parametrize("kind", ["unverifiable", "outage"])
async def test_an_unverified_role_map_ends_the_holders_sessions_and_writes_no_role(
    monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    store, _, service, tokens, pages = await _estate(("jdoe",), _ADMINS)
    try:
        user = await store.get_user_by_username("jdoe")
        assert user is not None and await store.get_user_role_ids(user.id) == ["administrator"]
        _refuse(monkeypatch, AD_ROLE_MAP, kind)
        plan = await service.reconcile_directory_sessions()
        assert plan.aborted is None
        assert [(r.username, r.reason) for r in plan.revocations] == [("jdoe", "roles_changed")]
        assert await service.identity_for_token(tokens["jdoe"]) is None
        # No role written from a map read as empty.
        assert await store.get_user_role_ids(user.id) == ["administrator"]
        action, slug, subject = _EXPECT[kind]
        assert await _audits(store, action) == [
            {"kind": "adset", "map": AD_ROLE_MAP, "reason": slug, "during": "reconcile"}
        ]
        (revoked,) = await _audits(store, "auth.ad_session_revoked")
        assert revoked["map_unverified"] is True and "roles" not in revoked
        expected = subject + (AD_ROLE_MAP if kind == "unverifiable" else "")
        assert [p.split("|")[0] for p in pages] == [expected]
    finally:
        await store.close()


@pytest.mark.parametrize("kind", ["unverifiable", "outage"])
async def test_an_unverified_scope_map_ends_a_scope_holders_session(
    monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    store, _, service, tokens, pages = await _estate(("jdoe",), _CHANNELS)
    try:
        _refuse(monkeypatch, AD_SCOPE_MAP, kind)
        plan = await service.reconcile_directory_sessions()
        assert [r.username for r in plan.revocations] == ["jdoe"]
        assert plan.revocations[0].scope_changed
        assert await service.identity_for_token(tokens["jdoe"]) is None
        action, slug, _ = _EXPECT[kind]
        assert [d["map"] for d in await _audits(store, action)] == [AD_SCOPE_MAP]
        assert len(pages) == 1
    finally:
        await store.close()


async def test_an_account_the_map_does_not_govern_keeps_its_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, _, service, tokens, pages = await _estate(("jdoe",))
    try:
        _refuse(monkeypatch, AD_ROLE_MAP, "unverifiable")
        plan = await service.reconcile_directory_sessions()
        assert plan.revocations == ()
        assert await service.identity_for_token(tokens["jdoe"]) is not None
        assert len(pages) == 1  # the map still pages
    finally:
        await store.close()


async def test_the_session_end_rides_the_breaker(monkeypatch: pytest.MonkeyPatch) -> None:
    """Seven holders past the five-account floor, all of the estate: the brake trips and nothing is
    applied, as on every trip, while the map still pages and audits."""
    names = tuple(f"admin{i}" for i in range(7))
    store, _, service, tokens, pages = await _estate(names, _ADMINS)
    try:
        _refuse(monkeypatch, AD_ROLE_MAP, "unverifiable")
        plan = await service.reconcile_directory_sessions()
        assert plan.aborted is not None and plan.revocations == ()
        for token in tokens.values():
            assert await service.identity_for_token(token) is not None
        assert len(await _audits(store, "integrity.authority_seal_unverifiable")) == 1
        assert len(pages) == 1
    finally:
        await store.close()


async def test_every_pass_that_meets_the_map_reports_it(monkeypatch: pytest.MonkeyPatch) -> None:
    store, _, service, _, pages = await _estate(("jdoe",))
    try:
        _refuse(monkeypatch, AD_ROLE_MAP, "unverifiable")
        for _ in range(2):
            await service.reconcile_directory_sessions()
        assert len(await _audits(store, "integrity.authority_seal_unverifiable")) == 2
        assert len(pages) == 2
    finally:
        await store.close()


async def test_a_holding_map_is_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    """Control: with both maps holding, no integrity row, no page, and the roles row unchanged."""
    store, _, service, tokens, pages = await _estate(("jdoe",), _ADMINS)
    try:
        plan = await service.reconcile_directory_sessions()
        assert plan.revocations == ()
        assert await service.identity_for_token(tokens["jdoe"]) is not None
        assert pages == []
        assert await _audits(store, "integrity.authority_seal_unverifiable") == []
    finally:
        await store.close()


# --- Postgres and SQL Server twins ----------------------------------------------------------------


class _RefusingSealer:
    def __init__(self, kind: str) -> None:
        self.kind = kind

    async def verify_held_async(self, *_args: Any) -> bool:
        raise _refusal(self.kind)


@pytest.mark.parametrize("kind", ["unverifiable", "outage"])
@pytest.mark.parametrize("backend", ["postgres", "sqlserver"])
async def test_a_server_store_map_reader_reports_and_reads_empty(backend: str, kind: str) -> None:
    module = importlib.import_module(f"messagefoundry.store.{backend}")
    cls = getattr(module, "PostgresStore" if backend == "postgres" else "SqlServerStore")
    store = cls.__new__(cls)
    store._seal_pager = SealPager()
    pages: list[str] = []
    store.seal_pager().arm(lambda subject, reason: pages.append(subject))
    sealer = _RefusingSealer(kind)

    async def get_ad_map(name: str) -> AdMap:
        return AdMap(name, pairs=((_ADMINS, "administrator"),), seal="vault:v5:synthetic")

    store.get_ad_map = get_ad_map
    store.row_sealer = lambda: sealer
    service = AuthService.__new__(AuthService)
    service._store = store
    written: list[tuple[str, dict[str, Any]]] = []

    async def audit(action: str, **kwargs: Any) -> None:
        written.append((action, json.loads(kwargs["detail"])))

    service._audit = audit  # type: ignore[method-assign]
    found, held = await service._reconcile_ad_map(AD_ROLE_MAP)
    assert found.pairs == () and held is False
    action, slug, subject = _EXPECT[kind]
    assert written == [
        (action, {"kind": "adset", "map": AD_ROLE_MAP, "reason": slug, "during": "reconcile"})
    ]
    assert pages == [subject + (AD_ROLE_MAP if kind == "unverifiable" else "")]
