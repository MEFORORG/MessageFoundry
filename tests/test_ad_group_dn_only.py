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
from messagefoundry.auth.ldap import (
    LdapAuthenticator,
    canonical_group_dn,
    is_group_dn,
    kerberos_principal,
)
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

#: A group whose name holds a ``#`` after its first character. RFC 4514 escapes ``#`` only at the
#: start of a value, and Active Directory writes it unescaped in ``memberOf``.
SHARP = "CN=C# Developers,OU=Groups,DC=example,DC=invalid"
SHARP_CANON = "cn=c# developers,ou=groups,dc=example,dc=invalid"


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
        "CN=MF-Admins, OU=Groups,DC=example",  # a space after a separator is padding
        "CN=C# Developers,DC=example",  # a "#" after a value's first character is literal
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
        "CN=MF-Admins,,DC=example",
        "CN=,DC=example",
        "CN=   ,DC=example",  # padding only: an empty value
        "CN=MF-Admins,DC=example,",  # a trailing separator
        "CN=#4142,DC=example",  # an unescaped leading "#" is a BER hex string
        'CN="MF-Admins",DC=example',  # a quoted value
        "CN=MF-Admins;DC=example",  # the old ";" separator
        "CN=MF-Admins,DC=example\\",  # a trailing lone backslash
        "CN=\\ff,DC=example",  # not UTF-8 once unescaped
        "C N=MF-Admins,DC=example",  # not an attribute type
        "CN=\ud800,DC=example",  # a lone surrogate cannot be encoded
        "example\\MF-Admins",
        "",
    ],
)
def test_anything_else_is_not_a_group_dn(value: str) -> None:
    assert not is_group_dn(value)
    assert canonical_group_dn(value) is None


# --- every spelling of one DN has one canonical form ---------------------------------------------


@pytest.mark.parametrize(
    ("spelling", "canonical"),
    [
        # The directory's own spelling, the RFC 4514 escape, and the hex escape of one "#".
        (SHARP, SHARP_CANON),
        ("cn=C\\# developers,ou=Groups,dc=example,dc=invalid", SHARP_CANON),
        ("CN=C\\23 Developers,OU=Groups,DC=example,DC=invalid", SHARP_CANON),
        # A comma escaped two ways, and a space after a separator.
        ("CN=Smith\\, Pat,OU=Groups,DC=example", "cn=smith\\, pat,ou=groups,dc=example"),
        ("CN=Smith\\2C Pat, OU=Groups, DC=example", "cn=smith\\, pat,ou=groups,dc=example"),
        # A multi-valued RDN in either order, with the attribute types in any case.
        ("CN=Ops+OU=Lab,DC=example", "cn=ops+ou=lab,dc=example"),
        ("ou=Lab+cn=Ops,DC=example", "cn=ops+ou=lab,dc=example"),
        # Escapes a canonical value must keep, and a multi-byte UTF-8 hex escape.
        # An escaped space at either end is hex-escaped, so the store's strip() cannot eat it.
        ("CN=\\#lead\\ ,DC=example", "cn=\\#lead\\20,dc=example"),
        ("CN=\\ lead,DC=example", "cn=\\20lead,dc=example"),
        # A tab, a line break and a no-break space are part of the value, hex-escaped.
        ("CN=a\tb\\0A,DC=example", "cn=a\\09b\\0a,dc=example"),
        ("CN=a\u00a0,DC=example", "cn=a\\c2\\a0,dc=example"),
        ("CN=a\\+b\\<c\\>,DC=example", "cn=a\\+b\\<c\\>,dc=example"),
        ("CN=Caf\\C3\\A9,DC=example", "cn=caf\\c3\\a9,dc=example"),
        # Non-ASCII is hex-escaped however it arrives, and only ASCII letters fold case.
        ("CN=Caf\u00e9,DC=example", "cn=caf\\c3\\a9,dc=example"),
        ("CN=\u00c4RZTE,DC=example", "cn=\\c3\\84rzte,dc=example"),
        ("CN=a\\00b,DC=example", "cn=a\\00b,dc=example"),
        # A dotted-OID attribute type. Three arcs, so it is not mistaken for an IP address.
        ("2.5.77=Ops,DC=example", "2.5.77=ops,dc=example"),
    ],
)
def test_each_spelling_has_one_canonical_form(spelling: str, canonical: str) -> None:
    assert canonical_group_dn(spelling) == canonical
    # Stable: canonicalising again changes nothing, and neither does the store's own fold.
    assert canonical_group_dn(canonical) == canonical
    assert canonical.strip().lower() == canonical


@pytest.mark.parametrize(
    ("one", "other"),
    [
        # An escaped "+" is part of a value; an unescaped one starts a second attribute.
        ("CN=a\\+OU=b,DC=example", "CN=a+OU=b,DC=example"),
        # An escaped space at either end is part of the value; an unescaped one is padding.
        ("CN=\\ a,DC=example", "CN=a,DC=example"),
        ("CN=a\\ ,DC=example", "CN=a,DC=example"),
        # A tab, a line break or a no-break space at either end is never padding.
        ("CN=MF-Admins\t,OU=Groups,DC=example", "CN=MF-Admins,OU=Groups,DC=example"),
        ("CN=MF-Admins\\0A,OU=Groups,DC=example", "CN=MF-Admins,OU=Groups,DC=example"),
        ("CN=MF-Admins,OU=Groups,DC=example\\c2\\a0", "CN=MF-Admins,OU=Groups,DC=example"),
        # An escaped backslash followed by "00" is not a NUL.
        ("CN=a\\5c00,DC=example", "CN=a\\00,DC=example"),
        # Only ASCII letters fold case. The Kelvin sign is not k, Georgian Mtavruli is not
        # Mkhedruli, and a non-ASCII capital is not its small letter.
        ("CN=\u212aiosk,DC=example", "CN=Kiosk,DC=example"),
        ("CN=\u1c90\u1c93,DC=example", "CN=\u10d0\u10d3,DC=example"),
        ("CN=\u00c4rzte,DC=example", "CN=\u00e4rzte,DC=example"),
        # Fullwidth letters, which a width-insensitive SQL collation would fold onto ASCII.
        ("CN=\uff2d\uff26-Admins,DC=example", "CN=MF-Admins,DC=example"),
        # A different unit is a different group, which is the point of #2610.
        (LEGIT, ROGUE),
    ],
)
def test_distinct_groups_keep_distinct_canonical_forms(one: str, other: str) -> None:
    """Review of the canonical form: a merge of two spellings is only safe while two different
    groups never merge. Each pair here names two groups, and each must canonicalise apart."""
    a, b = canonical_group_dn(one), canonical_group_dn(other)
    assert a is not None and b is not None
    assert a != b
    # The store strips and folds case on both sides; that must not merge them either. Nor can
    # a collation: the key is printable ASCII with no capital letter.
    assert a.strip().lower() != b.strip().lower()
    for key in (a, b):
        assert key.isascii() and key.isprintable() and key == key.lower(), key


def test_resolve_groups_counts_a_dropped_dn_at_debug(caplog: pytest.LogCaptureFixture) -> None:
    """A member DN with no canonical form is dropped, and the log says how many, never which."""
    with caplog.at_level("DEBUG", logger=ldap_mod.logger.name):
        got = _groups_of([LEGIT, 'CN="quoted",DC=example'])
    assert got == {LEGIT.lower()}
    dropped = [r for r in caplog.records if "dropped" in r.getMessage()]
    assert len(dropped) == 1 and dropped[0].levelname == "DEBUG"
    assert "1 group DN" in dropped[0].getMessage() and "quoted" not in dropped[0].getMessage()


async def test_a_key_too_long_once_canonical_is_refused(engine: Engine) -> None:
    """A key within the request model's 512 characters whose canonical form passes the 256 the
    SQL Server column holds is refused with a 400, not stored partway. Each non-ASCII letter takes
    six or more characters once escaped."""
    transport = await _admin_transport(engine)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        login = {"username": "boss", "password": PW, "provider": "local"}
        h = {"Authorization": f"Bearer {(await c.post('/auth/login', json=login)).json()['token']}"}
        key = "CN=" + "\u00e4" * 60 + ",OU=Groups,DC=example,DC=invalid"
        assert len(key) < 512
        body = {"entries": [{"ad_group": key, "role": Role.OPERATOR.value}]}
        r = await c.put("/ad-group-map", json=body, headers=h)
        assert r.status_code == 400, r.text
        assert "canonical form" in r.json()["detail"]
        assert (await c.get("/ad-group-map", headers=h)).json()["entries"] == []


async def test_a_pasted_key_with_a_line_break_still_maps(engine: Engine) -> None:
    """A route trims the key's outer white space before canonicalising it, so a key pasted with
    a trailing line break stores the same key as the bare one."""
    transport = await _admin_transport(engine)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        login = {"username": "boss", "password": PW, "provider": "local"}
        h = {"Authorization": f"Bearer {(await c.post('/auth/login', json=login)).json()['token']}"}
        body = {"entries": [{"ad_group": f"{LEGIT}\r\n", "role": Role.OPERATOR.value}]}
        assert (await c.put("/ad-group-map", json=body, headers=h)).status_code == 200
        got = (await c.get("/ad-group-map", headers=h)).json()["entries"]
        assert got == [{"ad_group": LEGIT.lower(), "role": Role.OPERATOR.value}]


def test_resolve_groups_canonicalises_direct_and_nested_dns() -> None:
    """``memberOf`` and the nested search both come back canonical, so a key written with an
    escape the directory does not use still names the group. A DN with no canonical form is
    dropped: no stored key can name it."""
    nested = [_Entry("CN=Ops+OU=Lab,OU=Groups,DC=example,DC=invalid", "unused")]
    got = _groups_of([SHARP, 'CN="quoted",DC=example'], nested)
    assert got == {SHARP_CANON, "cn=ops+ou=lab,ou=groups,dc=example,dc=invalid"}


async def test_a_multi_valued_rdn_in_either_order_matches(store: MessageStore) -> None:
    """A key that lists a multi-valued RDN's parts in the other order from the directory still
    maps the member. The key is canonicalised the way the routes do before the store write."""
    canonical = canonical_group_dn("OU=Lab+CN=Ops,OU=Groups,DC=example,DC=invalid")
    assert canonical is not None
    await store.set_ad_group_role_map([(canonical, Role.OPERATOR.value)])
    member = _groups_of(["CN=Ops+OU=Lab,OU=Groups,DC=example,DC=invalid"])
    assert await store.roles_for_ad_groups(member) == {Role.OPERATOR.value}


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


@pytest.mark.parametrize(
    "key",
    [
        SHARP,  # the spelling the directory itself writes
        "cn=C\\# developers,ou=Groups,dc=example,dc=invalid",  # escaped
        "CN=C\\23 Developers,OU=Groups,DC=example,DC=invalid",  # hex-escaped
    ],
)
async def test_a_group_with_a_sharp_in_its_name_can_be_mapped(engine: Engine, key: str) -> None:
    """The Lander's finding on PR 2107. Fails on ``ba38a0d850`` for the unescaped arm: ldap3's
    parser refused the ``#`` and the route answered 400. The two escaped arms were accepted there
    but stored a key the directory's unescaped DN never equalled, so the member got nothing. Every
    spelling now stores one canonical key, and a member whose ``memberOf`` carries the directory's
    own spelling gets the role and the channel."""
    transport = await _admin_transport(engine)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        login = {"username": "boss", "password": PW, "provider": "local"}
        h = {"Authorization": f"Bearer {(await c.post('/auth/login', json=login)).json()['token']}"}
        role = {"entries": [{"ad_group": key, "role": Role.OPERATOR.value}]}
        r = await c.put("/ad-group-map", json=role, headers=h)
        assert r.status_code == 200, r.text
        scope = {"entries": [{"ad_group": key, "channel": "IB_DEV"}]}
        r = await c.put("/ad-group-scope-map", json=scope, headers=h)
        assert r.status_code == 200, r.text
    member = _groups_of([SHARP])
    assert await engine.store.roles_for_ad_groups(member) == {Role.OPERATOR.value}
    assert await engine.store.channels_for_ad_groups(member) == {"IB_DEV"}


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
