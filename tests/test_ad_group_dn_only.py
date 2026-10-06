# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2610 limbs 1 and 4, and review point (c): the AD group maps key on full DNs only.

``_resolve_groups`` used to add each direct group's first CN, and each nested group's
``sAMAccountName``, beside its DN. So a map key written as a short name matched a same-named group in
any organisational unit, and anyone able to create one could take the roles mapped to it. The fix
has two halves, and each is pinned here: the resolver yields DNs only, and both map writes refuse a
key that is not a full DN. Every directory value below is synthetic.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import spnego

from messagefoundry.api import create_app
from messagefoundry.auth import ldap as ldap_mod
from messagefoundry.auth.ldap import LdapAuthenticator, is_group_dn, kerberos_principal
from messagefoundry.auth.permissions import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.store import MessageStore
from tests._admin_account import create_local_user_chosen

PW = "Sup3rSecret!!"

#: The group an administrator meant to map, and a same-named one somebody made in another unit.
LEGIT = "CN=MF-Admins,OU=Groups,DC=example,DC=invalid"
ROGUE = "CN=MF-Admins,OU=Contractors,DC=example,DC=invalid"


class _Entry:
    """The ldap3 entry surface the nested-group search reads: a DN and a ``sAMAccountName``."""

    def __init__(self, dn: str, sam: str) -> None:
        self.entry_dn = dn
        self._sam = sam

    def __contains__(self, name: str) -> bool:
        return name == "sAMAccountName"

    def __getitem__(self, name: str) -> Any:
        return type("_Attr", (), {"value": self._sam, "values": [self._sam]})()


class _Conn:
    """Answers the nested-group search with ``nested``. No referral."""

    def __init__(self, nested: list[_Entry]) -> None:
        self.entries: list[_Entry] = []
        self._nested = nested
        self.result: dict[str, object] | None = None

    def search(self, **_kw: object) -> None:
        self.result = {"result": 0}
        self.entries = self._nested


def _authenticator(*, nested: bool = True) -> LdapAuthenticator:
    return LdapAuthenticator(
        AuthSettings(
            ad_enabled=True,
            ad_server="ldaps://dc.example.invalid",
            ad_user_search_base="DC=example,DC=invalid",
            ad_group_search_base="DC=example,DC=invalid" if nested else None,
            ad_bind_dn="CN=svc,DC=example,DC=invalid",
            ad_bind_password="synthetic",
        )
    )


def _groups_of(member_of: list[str], nested: list[_Entry] | None = None) -> frozenset[str]:
    auth = _authenticator(nested=nested is not None)
    return auth._resolve_groups(
        _Conn(nested or []), "CN=pat,OU=Users,DC=example,DC=invalid", member_of
    )


# --- the resolver yields DNs only -----------------------------------------------------------------


def test_resolve_groups_yields_each_groups_dn_and_no_short_name() -> None:
    """Fails on the unfixed tree: it also yielded ``mf-admins`` (the direct group's CN) and
    ``mf-nested-sam`` (the nested group's ``sAMAccountName``)."""
    nested = [_Entry("CN=MF-Nested,OU=Groups,DC=example,DC=invalid", "MF-Nested-Sam")]
    assert _groups_of([ROGUE], nested) == {
        ROGUE.lower(),
        "cn=mf-nested,ou=groups,dc=example,dc=invalid",
    }


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "s.db")
    # initialize() seeds the built-in roles the map's foreign key names.
    await AuthService(s, AuthSettings(require_mfa=False)).initialize()
    yield s
    await s.close()


async def test_a_same_named_group_in_another_unit_gets_no_role(store: MessageStore) -> None:
    """The map holds the legitimate group's DN. Its member gets the role (the control); a member of
    the same-named group in another unit gets nothing."""
    await store.set_ad_group_role_map([(LEGIT, Role.ADMINISTRATOR.value)])
    assert await store.roles_for_ad_groups(_groups_of([LEGIT])) == {Role.ADMINISTRATOR.value}
    assert await store.roles_for_ad_groups(_groups_of([ROGUE])) == set()


async def test_a_stored_short_name_key_matches_no_group(store: MessageStore) -> None:
    """A short-name key written before this item stays in the store, and now matches nothing.
    Fails on the unfixed tree: the rogue group's CN matched it and granted Administrator. The
    store is written directly because the routes now refuse such a key; zero deployments, so no
    migration rewrites one."""
    await store.set_ad_group_role_map([("MF-Admins", Role.ADMINISTRATOR.value)])
    await store.set_ad_group_scope_map([("MF-Admins", "*")])
    rogue = _groups_of([ROGUE])
    assert await store.roles_for_ad_groups(rogue) == set()
    assert await store.channels_for_ad_groups(rogue) == set()


# --- the shape check ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        LEGIT,
        LEGIT.lower(),
        "CN=Smith\\, Pat,OU=Groups,DC=example,DC=invalid",
        "CN=A+OU=B,DC=example",  # a multi-valued first RDN is still followed by a second RDN
        f"  {LEGIT}  ",  # the store strips; so does the check
    ],
)
def test_a_full_dn_is_a_group_dn(value: str) -> None:
    assert is_group_dn(value)


@pytest.mark.parametrize(
    "value",
    [
        "MF-Admins",  # a short name
        "CN=MF-Admins",  # one RDN names no unit
        "CN=A+OU=B",  # one multi-valued RDN is still one RDN
        "CN=MF-Admins, OU=Groups,DC=example",  # a space after a separator
        "CN=MF-Admins,,DC=example",
        "CN=,DC=example",
        "example\\MF-Admins",
        "",
    ],
)
def test_anything_else_is_not_a_group_dn(value: str) -> None:
    assert not is_group_dn(value)


# --- both PUT routes refuse a short-name key ------------------------------------------------------


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "api.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


async def _admin_transport(engine: Engine) -> httpx.ASGITransport:
    service = AuthService(
        engine.store, AuthSettings(admin_write_min_interval_seconds=0, require_mfa=False)
    )
    await service.initialize()
    boss_id = await create_local_user_chosen(
        service,
        username="boss",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.ADMINISTRATOR.value],
        actor="test",
    )
    user = await engine.store.get_user(boss_id)
    assert user is not None and user.password_hash is not None
    # Admin-created accounts force first-login rotation (WP-L3-12); clear it, keeping the hash.
    await engine.store.set_password(
        boss_id,
        password_hash=user.password_hash,
        must_change_password=False,
        password_generated=False,
    )
    return httpx.ASGITransport(app=create_app(engine, auth=service))


@pytest.mark.parametrize(
    ("path", "field", "value"),
    [
        ("/ad-group-map", "role", Role.ADMINISTRATOR.value),
        ("/ad-group-scope-map", "channel", "*"),
    ],
)
async def test_a_map_write_refuses_a_short_name_and_takes_a_dn(
    engine: Engine, path: str, field: str, value: str
) -> None:
    """Fails on the unfixed tree: both routes stored ``MF-Admins`` and answered 200."""
    transport = await _admin_transport(engine)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        login = {"username": "boss", "password": PW, "provider": "local"}
        h = {"Authorization": f"Bearer {(await c.post('/auth/login', json=login)).json()['token']}"}
        short = {"entries": [{"ad_group": "MF-Admins", field: value}]}
        r = await c.put(path, json=short, headers=h)
        assert r.status_code == 400, r.text
        assert "full distinguished name" in r.json()["detail"]
        assert (await c.get(path, headers=h)).json()["entries"] == []

        # One bad key refuses the whole write: nothing from the same body is stored.
        mixed = {"entries": [{"ad_group": LEGIT, field: value}, {"ad_group": "CN=X", field: value}]}
        assert (await c.put(path, json=mixed, headers=h)).status_code == 400
        assert (await c.get(path, headers=h)).json()["entries"] == []

        full = {"entries": [{"ad_group": LEGIT, field: value}]}
        assert (await c.put(path, json=full, headers=h)).status_code == 200
        got = (await c.get(path, headers=h)).json()["entries"]
        assert got == [{"ad_group": LEGIT.lower(), field: value}]


# --- review point (c): an incomplete SPNEGO context names no client ------------------------------


@pytest.mark.parametrize(("complete", "expected"), [(False, None), (True, "alice")])
def test_kerberos_principal_needs_a_complete_context(
    monkeypatch: pytest.MonkeyPatch, complete: bool, expected: str | None
) -> None:
    """Fails on the unfixed tree for ``complete=False``: it read ``client_principal`` regardless and
    answered ``alice``. The ``True`` arm is the control."""

    class _Server:
        client_principal = "alice@EXAMPLE.INVALID"

        def __init__(self) -> None:
            self.complete = complete

        def step(self, _token: bytes) -> None:
            return None

    monkeypatch.setattr(spnego, "server", lambda **_kw: _Server())
    monkeypatch.setattr(ldap_mod, "_kerberos_capable", lambda: True)
    assert kerberos_principal(b"token", AuthSettings()) == expected


class _Inner:
    def __init__(self, complete: bool, protocol: str) -> None:
        self.complete = complete
        self.negotiated_protocol = protocol


def _negotiate_server(*, outer: bool, inner: bool | None, protocol: str = "kerberos") -> Any:
    """A pyspnego Negotiate wrapper (the Linux acceptor) with its two completion flags set by hand.
    ``inner=None`` stands for a wrapper that chose no mechanism. ``__init__`` is skipped: it would
    look for real credentials."""
    from spnego._negotiate import NegotiateProxy

    class _Negotiate(NegotiateProxy):
        client_principal = "alice@EXAMPLE.INVALID"

        @property
        def complete(self) -> bool:
            return outer

        @property
        def _context(self) -> Any:
            if inner is None:
                raise KeyError("no mechanism chosen")
            return _Inner(inner, protocol)

        def step(self, *_a: Any, **_kw: Any) -> None:
            return None

    return object.__new__(_Negotiate)


@pytest.mark.parametrize(
    ("outer", "inner", "protocol", "expected"),
    [
        # The Windows-client case: the wrapper waits on a mechListMIC, the Kerberos context finished.
        (False, True, "kerberos", "alice"),
        (False, False, "kerberos", None),
        (False, None, "kerberos", None),
        (True, True, "kerberos", "alice"),
        # Only a finished Kerberos context counts; no other inner mechanism signs in this way.
        (False, True, "ntlm", None),
    ],
)
def test_the_negotiate_wrapper_is_judged_by_its_inner_context(
    monkeypatch: pytest.MonkeyPatch,
    outer: bool,
    inner: bool | None,
    protocol: str,
    expected: str | None,
) -> None:
    """Review of this item: reading only the wrapper's own ``complete`` refused every Windows client
    where pyspnego's own wrapper runs, because it stays incomplete waiting on a leg this acceptor
    never takes. The first arm pins that such a client still signs in; the others that an unfinished
    or non-Kerberos inner context does not. The stub states pyspnego 0.12's shape rather than
    driving a real token through it."""
    server = _negotiate_server(outer=outer, inner=inner, protocol=protocol)
    monkeypatch.setattr(spnego, "server", lambda **_kw: server)
    monkeypatch.setattr(ldap_mod, "_kerberos_capable", lambda: True)
    assert kerberos_principal(b"token", AuthSettings()) == expected
