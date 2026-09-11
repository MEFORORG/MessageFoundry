# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""BACKLOG #1471: an AD account is bound to the directory's IMMUTABLE id, not to its recyclable name.

**WHAT IS AND IS NOT EXERCISED HERE, stated so a green is not over-read.** There is no Active
Directory in CI and there never has been. ``_find_user`` itself runs -- it takes a connection, so a
double can drive it, and the ``pragma: no cover - needs real AD`` markers in ``auth/ldap.py`` sit on
the ``LDAPException`` handlers around it rather than on the lookup. What no test here can reach is
the bind and the wire: **this is not evidence that a real domain controller returns what the double
returns**, only that the engine asks for the attribute and carries what it gets. The recycle itself
is driven at the SERVICE layer, where the store is real (SQLite, in memory) and the decision under
test lives.

The acceptance test the ledger row names is
``test_a_recycled_sam_account_name_does_not_adopt_the_departed_operators_row``. Synthetic data only;
nothing here touches PHI.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

import pytest

from messagefoundry.auth import Role
from messagefoundry.auth import ldap as ldap_module
from messagefoundry.auth.identity import AuthProvider
from messagefoundry.auth.ldap import (
    AdPrincipal,
    LdapAuthenticator,
    _object_guid,
    normalise_object_guid,
    object_guid_filter_value,
)
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore

# One account object, two spellings of the SAME identity: the 16 bytes as they arrive on the wire,
# and the braced upper-case string ldap3's own formatter produces. Microsoft's GUID layout is
# little-endian in its first three fields, so the bytes below are the canonical form byte-swapped --
# reading them big-endian yields a well-formed UUID that names a DIFFERENT object.
GUID_A_BYTES = bytes.fromhex("7856341234123412123456789abcdef0")
GUID_A_TEXT = "12345678-1234-1234-1234-56789abcdef0"
GUID_A_BRACED = "{12345678-1234-1234-1234-56789ABCDEF0}"
GUID_B_TEXT = str(uuid.UUID("fedcba98-7654-3210-fedc-ba9876543210"))

# The SAME 16 bytes as a directory hands back when no formatter is registered for the attribute: the
# octets decoded as text rather than rendered as a GUID. ``normalise_object_guid`` refuses it -- it is
# a 16-character string, not a parseable UUID -- and that refusal is what lets
# ``test_the_raw_wire_bytes_win_over_whatever_formatter_ldap3_registered`` fail when the preference it
# is named for is deleted. A braced string beside its own bytes cannot: both arms normalise alike.
GUID_A_UNFORMATTED = GUID_A_BYTES.decode("latin-1")


@pytest.fixture(autouse=True)
def _reset_the_warning_latch() -> None:
    """``_object_guid`` reports each unusable shape ONCE per process, so the latch has to start empty
    or a test's own warning depends on which tests ran first."""
    ldap_module._object_guid_shapes_warned.clear()


# --- the boundary: one identity, one text form ---------------------------------------------------


def test_the_wire_bytes_and_the_formatted_string_normalise_to_the_same_text() -> None:
    """The whole point of normalising at the boundary: an id that renders two ways is not an id.

    Both arms are the same directory object. If they disagreed, a row bound through one shape would
    be invisible to a login arriving through the other -- which reads exactly like a recycled name
    and would silently mint a second account.
    """
    assert normalise_object_guid(GUID_A_BYTES) == GUID_A_TEXT
    assert normalise_object_guid(GUID_A_BRACED) == GUID_A_TEXT
    assert normalise_object_guid(GUID_A_BYTES) == normalise_object_guid(GUID_A_BRACED)


def test_the_fixture_can_tell_the_two_byte_orders_apart() -> None:
    """A control on the INSTRUMENT, not on the engine: it asserts nothing about MessageFoundry code.

    The test above discriminates byte order only because these 16 bytes read differently the two
    ways. Pick a palindromic value and it would pass over an implementation using ``bytes=`` instead
    of ``bytes_le=``, and nothing would say so. This is the assertion that the fixture has the
    property the other test's conclusion rests on.
    """
    assert str(uuid.UUID(bytes=GUID_A_BYTES)) != GUID_A_TEXT


@pytest.mark.parametrize(
    "value",
    [
        b"",
        b"\x00" * 15,
        b"\x00" * 17,
        "not-a-guid",
        "",
        12345,
        None,
    ],
)
def test_a_value_that_is_not_a_guid_normalises_to_nothing(value: object) -> None:
    """Refused rather than coerced. A partially-parsed identifier is worse than an absent one: the
    caller's fallback is name resolution, which is at least a rule somebody wrote down."""
    assert normalise_object_guid(value) is None


class _FakeAttr:
    """One ``ldap3`` attribute. ``raw_values`` is modelled because ``_object_guid`` prefers it, which
    the older entry doubles in ``tests/test_ldap_timeouts`` and ``tests/test_auth_hardening`` predate;
    ``values`` is modelled because ``_multi`` reads it for ``memberOf``."""

    def __init__(self, value: Any, raw: bytes | None = None) -> None:
        self.value = value
        self.values = value if isinstance(value, list) else [value]
        if raw is not None:
            self.raw_values = [raw]


class _FakeEntry:
    """The minimal ``ldap3`` entry surface ``_object_guid`` and ``_find_user`` touch."""

    def __init__(self, attrs: dict[str, _FakeAttr], *, dn: str = "CN=x,DC=x") -> None:
        self._attrs = attrs
        self.entry_dn = dn

    def __contains__(self, name: str) -> bool:
        return name in self._attrs

    def __getitem__(self, name: str) -> _FakeAttr:
        return self._attrs[name]


def test_the_raw_wire_bytes_win_over_whatever_formatter_ldap3_registered() -> None:
    """``raw_values`` is read in preference to ``value``, ON A PAIR THAT CAN TELL THE TWO APART.

    The pairing that reads naturally -- the braced string beside its own bytes -- cannot, and this
    test used to use it. The first test in this file proves both of those arms normalise to the same
    text, so both sides of the choice returned the same answer: the preference could be deleted
    outright and the assertion still held. Measured by mutation, and the mutation stayed green.

    What the preference actually buys is independence from whichever formatter ``ldap3`` registered
    for the attribute, so the discriminating case is a ``value`` the normaliser REFUSES beside raw
    bytes it accepts. Reading ``value`` there yields no identity at all, which is the real failure:
    the login falls back to the recyclable name and nothing downstream says why.
    """
    assert normalise_object_guid(GUID_A_UNFORMATTED) is None, (
        "the fixture stopped discriminating: this value normalises on its own, so the assertion "
        "below would pass with the raw_values preference deleted"
    )
    entry = _FakeEntry({"objectGUID": _FakeAttr(GUID_A_UNFORMATTED, raw=GUID_A_BYTES)})
    assert _object_guid(entry) == GUID_A_TEXT


def test_the_two_spellings_of_one_account_still_agree_through_the_entry() -> None:
    """The ordinary case the test above gave up in order to discriminate: a registered formatter and
    the wire bytes name the same object, so which one is read cannot change the identity."""
    both = _FakeEntry({"objectGUID": _FakeAttr(GUID_A_BRACED, raw=GUID_A_BYTES)})
    assert _object_guid(both) == GUID_A_TEXT


def test_a_formatted_string_alone_is_still_read() -> None:
    entry = _FakeEntry({"objectGUID": _FakeAttr(GUID_A_BRACED)})
    assert _object_guid(entry) == GUID_A_TEXT


def test_an_absent_attribute_reads_as_no_identity_and_still_warns(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A directory that never returns the attribute is the quietest way to be on the old path, so it
    is reported. Silence here would let a site assume a control that is not running for it."""
    with caplog.at_level(logging.WARNING, logger="messagefoundry.auth.ldap"):
        assert _object_guid(_FakeEntry({})) is None
    assert [r for r in caplog.records if r.name == "messagefoundry.auth.ldap"]


def test_an_unreadable_value_warns_and_never_logs_the_value(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The fallback is the recycle-vulnerable path, so it is not allowed to be silent -- and the
    warning names the SHAPE, never the identifier, which names a directory account."""
    entry = _FakeEntry({"objectGUID": _FakeAttr("nonsense")})
    with caplog.at_level(logging.WARNING, logger="messagefoundry.auth.ldap"):
        assert _object_guid(entry) is None
    records = [r for r in caplog.records if r.name == "messagefoundry.auth.ldap"]
    assert len(records) == 1
    message = records[0].getMessage()
    assert "BACKLOG #1471" in message
    assert "nonsense" not in message


def test_the_warning_fires_once_per_shape_and_not_once_per_read(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """``_find_user`` is not login-only: the session reconciler probes it per user per pass, so one
    line per read would be tens of thousands a day, all carrying what the first one carried. "Warns"
    and "warns once" are different controls and only one of them is usable."""
    entry = _FakeEntry({"objectGUID": _FakeAttr("nonsense")})
    with caplog.at_level(logging.WARNING, logger="messagefoundry.auth.ldap"):
        for _ in range(5):
            assert _object_guid(entry) is None
        # A DIFFERENT shape is a different fact and is still reported -- the latch must not swallow
        # the second cause once it has seen a first.
        assert _object_guid(_FakeEntry({})) is None
    records = [r for r in caplog.records if r.name == "messagefoundry.auth.ldap"]
    assert len(records) == 2


class _FakeConn:
    """Records the search kwargs and answers with one entry -- the shape ``tests/test_auth_hardening``
    already uses to drive ``_find_user`` without a directory."""

    def __init__(self, entry: _FakeEntry) -> None:
        self.entries = [entry]
        self.kwargs: dict[str, Any] = {}

    def search(self, **kwargs: Any) -> None:
        self.kwargs = kwargs


def _authenticator() -> LdapAuthenticator:
    return LdapAuthenticator(
        AuthSettings(
            ad_enabled=True,
            ad_server="ldaps://x",
            ad_user_search_base="DC=x",
            ad_bind_dn="CN=svc,DC=x",
            ad_bind_password="x",
        )
    )


def test_the_user_search_asks_for_the_immutable_id_and_carries_it_out() -> None:
    """END TO END THROUGH THE REAL LOOKUP, because the two halves fail independently.

    A search that never ASKS for ``objectGUID`` leaves the column NULL forever; a search that asks
    and never threads the value into the returned mapping does the same, and the first assertion
    alone would not see it. ``_find_user`` carries no ``pragma: no cover``, so both run here.
    """
    entry = _FakeEntry(
        {
            "sAMAccountName": _FakeAttr("jsmith"),
            "objectGUID": _FakeAttr(GUID_A_BRACED, raw=GUID_A_BYTES),
            "displayName": _FakeAttr("J Smith"),
            "mail": _FakeAttr("jsmith@example.org"),
            "userAccountControl": _FakeAttr("512"),
        },
        dn="CN=jsmith,DC=x",
    )
    conn = _FakeConn(entry)
    info = _authenticator()._find_user(conn, "jsmith")
    assert "objectGUID" in conn.kwargs["attributes"]
    assert info is not None
    assert info["object_id"] == GUID_A_TEXT


def test_a_directory_entry_without_the_attribute_yields_no_identity() -> None:
    """The fallback arm of the same lookup: the mapping carries ``None``, not a fabricated id."""
    entry = _FakeEntry(
        {
            "sAMAccountName": _FakeAttr("jsmith"),
            "displayName": _FakeAttr("J Smith"),
            "mail": _FakeAttr("jsmith@example.org"),
            "userAccountControl": _FakeAttr("512"),
        },
        dn="CN=jsmith,DC=x",
    )
    info = _authenticator()._find_user(_FakeConn(entry), "jsmith")
    assert info is not None and info["object_id"] is None


# --- the producers: the two entry points that put the id ON the principal ------------------------
#
# THE ONLY PRODUCERS OF ``AdPrincipal.directory_object_id`` ARE ``authenticate`` AND
# ``resolve_principal``, and until these tests landed nothing asserted that either one copies the
# looked-up value onto what it returns. Measured: deleting ``directory_object_id=info["object_id"]``
# from either method left the WHOLE SUITE GREEN. The service tests all build an ``AdPrincipal`` by
# hand, the lookup tests above stop at the returned mapping, and the entry doubles in
# ``tests/test_ldap_timeouts`` carry no ``objectGUID`` -- so the assignment was invisible three ways
# at once, and mypy cannot see it either because the dataclass field defaults to None.
#
# What that would ship: a site on AD gets ``directory_object_id=None`` on every login through the
# dropped method, so new rows would bind to nothing and the recycle hole would reopen. Worse for an
# account already bound -- including one bound moments earlier over the OTHER method, since Kerberos
# and password take one each -- which would then fail the id check in ``_complete_ad_login`` and be
# refused as ``directory_identity_conflict`` on every attempt.


def _install_directory(monkeypatch: pytest.MonkeyPatch, entry: _FakeEntry) -> None:
    """Replace ``ldap3.Server`` / ``ldap3.Connection`` so the REAL entry points run against ``entry``.

    Deliberately not the ``_FakeConn`` above: that one is handed straight to ``_find_user`` and skips
    everything the entry points do with what it returns, which is the step under test here.
    """
    import ldap3

    class FakeServer:
        def __init__(self, host: Any = None, **kwargs: Any) -> None: ...

    class FakeConnection:
        def __init__(self, server: Any = None, **kwargs: Any) -> None:
            self.entries: list[_FakeEntry] = []

        def __enter__(self) -> FakeConnection:
            return self

        def __exit__(self, *exc: object) -> None:
            # None, not False: both are falsy and neither swallows, but the annotation says so.
            return None

        def search(self, **kwargs: Any) -> bool:
            self.entries = [entry]
            return True

        def bind(self) -> bool:
            return True

        def unbind(self) -> None: ...

    monkeypatch.setattr(ldap3, "Server", FakeServer)
    monkeypatch.setattr(ldap3, "Connection", FakeConnection)


def _directory_entry(guid: _FakeAttr | None) -> _FakeEntry:
    """One enabled AD account, with ``objectGUID`` present or absent. ``userAccountControl`` is 512
    (a normal enabled account); 0x2 would be refused by the lookup before any of this is reached."""
    attrs = {
        "sAMAccountName": _FakeAttr("jsmith"),
        "displayName": _FakeAttr("J Smith"),
        "mail": _FakeAttr("jsmith@example.org"),
        "memberOf": _FakeAttr(["CN=MF-Ops,DC=x"]),
        "userAccountControl": _FakeAttr("512"),
    }
    if guid is not None:
        attrs["objectGUID"] = guid
    return _FakeEntry(attrs, dn="CN=jsmith,DC=x")


def _drive(name: str, auth: LdapAuthenticator) -> AdPrincipal | None:
    """Call one entry point by name. Both take a username; only one takes a password, which is why
    this exists rather than a bare ``getattr``."""
    if name == "authenticate":
        return auth.authenticate("jsmith", "synthetic-user-pw")
    return auth.resolve_principal("jsmith")


#: The two methods that build an ``AdPrincipal``. Parametrised so each is a SEPARATELY NAMED case
#: that fails on its own -- dropping the assignment from one must not be masked by the other.
_ENTRY_POINTS = ["authenticate", "resolve_principal"]


@pytest.mark.parametrize("entry_point", _ENTRY_POINTS)
def test_the_entry_point_carries_the_immutable_id_onto_the_principal(
    entry_point: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The producer's own assertion: the value the lookup read reaches the returned principal.

    ``_complete_ad_login`` resolves the row by ``principal.directory_object_id`` and by nothing else,
    so an id that stops at the lookup's return mapping is an id the engine never uses.
    """
    _install_directory(monkeypatch, _directory_entry(_FakeAttr(GUID_A_BRACED, raw=GUID_A_BYTES)))
    principal = _drive(entry_point, _authenticator())
    assert principal is not None, f"{entry_point} did not reach a principal at all"
    assert principal.username == "jsmith"
    assert principal.directory_object_id == GUID_A_TEXT, (
        f"{entry_point} returned a principal carrying {principal.directory_object_id!r} rather than "
        "the directory's immutable id -- every row it binds would bind to nothing (BACKLOG #1471)"
    )


@pytest.mark.parametrize("entry_point", _ENTRY_POINTS)
def test_the_entry_point_reports_no_identity_rather_than_inventing_one(
    entry_point: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The fallback arm through the same real method: a directory that returns no ``objectGUID``
    yields ``None`` on the principal -- not the string ``"None"``, which would key a row."""
    _install_directory(monkeypatch, _directory_entry(None))
    principal = _drive(entry_point, _authenticator())
    assert principal is not None
    assert principal.directory_object_id is None


# --- the service: who a directory login is -------------------------------------------------------


def _principal(
    username: str, object_id: str | None, *, group: str = "cn=mf-ops,dc=x"
) -> AdPrincipal:
    return AdPrincipal(
        username=username,
        display_name=f"{username} Example",
        email=f"{username}@example.org",
        dn=f"CN={username},DC=x",
        groups=frozenset({group}),
        directory_object_id=object_id,
    )


class _FakeLdap:
    """Stands in for the directory. These tests drive ``_complete_ad_login`` with a principal
    directly -- the LDAP lookup itself is covered above, against the entry double."""

    def authenticate(self, username: str, password: str) -> AdPrincipal | None:
        return None

    def resolve_principal(self, username: str) -> AdPrincipal | None:
        return None


async def _service(store: MessageStore) -> AuthService:
    settings = AuthSettings(
        ad_enabled=True,
        ad_server="ldaps://x",
        ad_user_search_base="DC=x",
        ad_bind_dn="CN=svc,DC=x",
        ad_bind_password="x",
    )
    service = AuthService(store, settings, ldap=_FakeLdap())  # type: ignore[arg-type]
    await service.initialize()
    await service.set_ad_group_map([("CN=MF-Ops,DC=x", "operator")], actor="admin")
    return service


async def test_a_first_directory_login_binds_the_row_to_the_immutable_id() -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store)
        out = await service._complete_ad_login(
            _principal("jsmith", GUID_A_TEXT), None, mfa_verified=True
        )
        assert out.ok
        row = await store.get_user_by_username("jsmith")
        assert row is not None
        assert row.directory_object_id == GUID_A_TEXT
        assert row.auth_provider == AuthProvider.AD.value
        # The id-keyed read finds the same row the name-keyed one does, which is what makes the
        # resolver's lookup path real rather than a column nobody consults.
        by_id = await store.get_user_by_directory_object_id(GUID_A_TEXT)
        assert by_id is not None and by_id.id == row.id
    finally:
        await store.close()


async def test_the_same_account_signing_in_again_reuses_its_row() -> None:
    """The must-not-fire arm: binding by id must not mint a second row per login."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store)
        first = await service._complete_ad_login(
            _principal("jsmith", GUID_A_TEXT), None, mfa_verified=True
        )
        second = await service._complete_ad_login(
            _principal("jsmith", GUID_A_TEXT), None, mfa_verified=True
        )
        assert first.ok and second.ok
        assert first.identity is not None and second.identity is not None
        assert first.identity.user_id == second.identity.user_id
        named = [u for u in await store.list_users() if u.username == "jsmith"]
        assert len(named) == 1
    finally:
        await store.close()


async def test_a_recycled_sam_account_name_does_not_adopt_the_departed_operators_row() -> None:
    """THE ACCEPTANCE TEST the ledger row names: a directory-side name reuse, with the MessageFoundry
    row left in place, must not hand the new holder the old account.

    The departed operator's ``user_id`` is what uploaded-file ownership, the per-uploader quota and
    saved search presets key on, so adopting the row hands over all three at once, with nothing
    anywhere reporting it.
    """
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store)
        out = await service._complete_ad_login(
            _principal("jsmith", GUID_A_TEXT), None, mfa_verified=True
        )
        assert out.ok and out.identity is not None
        departed_id = out.identity.user_id
        roles_before = set(await store.get_user_role_ids(departed_id))

        # The directory deletes jsmith and issues the name to somebody else. Same name, new object.
        recycled = await service._complete_ad_login(
            _principal("jsmith", GUID_B_TEXT), None, mfa_verified=True
        )
        assert not recycled.ok, "a recycled name adopted the departed operator's account"
        assert recycled.token is None and recycled.identity is None
        assert recycled.reason == "directory_identity_conflict"

        # The old row is untouched: same id, same binding, same roles. A refusal that silently
        # rewrote the row would fail the login and still transfer the account.
        row = await store.get_user_by_username("jsmith")
        assert row is not None
        assert row.id == departed_id
        assert row.directory_object_id == GUID_A_TEXT
        assert set(await store.get_user_role_ids(departed_id)) == roles_before
        assert await store.get_user_by_directory_object_id(GUID_B_TEXT) is None

        # And the refusal is on the record, with a closed-set reason and no directory-supplied text.
        rows = await store.list_audit(action="auth.login_failed", limit=10)
        assert any("directory_identity_conflict" in str(r["detail"]) for r in rows)
    finally:
        await store.close()


async def test_the_recycled_holder_gets_their_own_row_once_the_name_no_longer_collides() -> None:
    """The other half of the same rule, and the reason the refusal above is not a dead end: a new
    directory object is a new account. It is refused only while the stale row still holds the name."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store)
        first = await service._complete_ad_login(
            _principal("jsmith", GUID_A_TEXT), None, mfa_verified=True
        )
        assert first.ok and first.identity is not None
        second = await service._complete_ad_login(
            _principal("jsmith2", GUID_B_TEXT), None, mfa_verified=True
        )
        assert second.ok and second.identity is not None
        assert second.identity.user_id != first.identity.user_id
        row = await store.get_user_by_username("jsmith2")
        assert row is not None and row.directory_object_id == GUID_B_TEXT
    finally:
        await store.close()


async def test_a_renamed_account_keeps_its_row_and_takes_the_new_name() -> None:
    """A directory-side rename keeps the row AND refreshes the cached username (BACKLOG #1532).

    **This test asserted the opposite until #1532, and the history is the point.** Before the
    binding, a rename resolved to nothing and minted a SECOND account, silently orphaning the uploads
    and presets keyed to the first. BACKLOG #1471 made the id find the row and left the stored name
    as created -- which is what left ``reconcile_directory_sessions`` probing a name the directory no
    longer answers to, revoking the renamed person's sessions on a loop. #1532 re-keyed that probe and
    made the name follow the directory that owns it.

    Both halves are asserted, because each alone would pass under a wrong implementation: the row must
    not move (a fresh row would pass a name check), and the name must move (a stale name would pass an
    id check).
    """
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store)
        first = await service._complete_ad_login(
            _principal("jsmith", GUID_A_TEXT), None, mfa_verified=True
        )
        assert first.ok and first.identity is not None
        renamed = await service._complete_ad_login(
            _principal("jsmith-married", GUID_A_TEXT), None, mfa_verified=True
        )
        assert renamed.ok and renamed.identity is not None
        assert renamed.identity.user_id == first.identity.user_id, "the rename minted a second row"

        row = await store.get_user_by_username("jsmith-married")
        assert row is not None, "the login did not copy the directory's new name down"
        assert row.id == first.identity.user_id
        assert row.directory_object_id == GUID_A_TEXT
        assert await store.get_user_by_username("jsmith") is None, (
            "the old name outlived the rename"
        )
        # ONE directory row, not two. The id-keyed resolve is what makes that true, and the count is
        # the control: asserting only that the new name resolves would pass on an implementation that
        # minted a second row and left the first behind. Counted over AD rows rather than every row,
        # because ``initialize()`` provisions a LOCAL bootstrap administrator that is not the subject.
        ad_rows = [u for u in await store.list_users() if u.auth_provider == AuthProvider.AD.value]
        assert len(ad_rows) == 1
    finally:
        await store.close()


async def test_a_login_renamed_onto_a_taken_name_is_refused() -> None:
    """A rename into a name another row holds is refused by #1471's guard, BEFORE #1532's refresh.

    ``username`` is ``NOT NULL UNIQUE``, so one name cannot serve two rows. **On the LOGIN path the
    collision never reaches the refresh**: ``_complete_ad_login`` reads the row holding the presented
    name first, finds an id that disagrees with the presented one, and refuses. That ordering is
    BACKLOG #1471's and #1532 deliberately did not change it -- proceeding would evaluate a login for
    one directory account while a different account's row held the name.

    **So the refresh's own collision branch is reached from the RECONCILER, not from here** -- that
    pass has no such guard, because it probes an account it has already identified. Recorded because
    the obvious reading is that both callers reach it, and a reader who believes that will look for
    the login-path coverage this test says does not exist.

    The cost is the residual BACKLOG #1471 already states: the renamed person cannot sign in until an
    operator removes the stale row. Fail-closed, audited, and recoverable.
    """
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store)
        mine = await service._complete_ad_login(
            _principal("jsmith", GUID_A_TEXT), None, mfa_verified=True
        )
        assert mine.ok and mine.identity is not None
        squatter = await service._complete_ad_login(
            _principal("jsmith-married", GUID_B_TEXT), None, mfa_verified=True
        )
        assert squatter.ok and squatter.identity is not None

        # The directory now renames the FIRST account onto the name the second one holds.
        out = await service._complete_ad_login(
            _principal("jsmith-married", GUID_A_TEXT), None, mfa_verified=True
        )
        assert not out.ok and out.reason == "directory_identity_conflict"

        # Neither row moved, and no third row was minted.
        still_mine = await store.get_user_by_directory_object_id(GUID_A_TEXT)
        assert still_mine is not None and still_mine.username == "jsmith"
        other = await store.get_user_by_username("jsmith-married")
        assert other is not None and other.id == squatter.identity.user_id
        ad_rows = [u for u in await store.list_users() if u.auth_provider == AuthProvider.AD.value]
        assert len(ad_rows) == 2
    finally:
        await store.close()


async def test_a_bound_row_is_refused_to_a_login_that_presents_no_identity() -> None:
    """An identity that cannot be checked is not an identity that matches. A directory that stops
    returning ``objectGUID`` gets an audited refusal, not a quiet return to name resolution."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store)
        assert (
            await service._complete_ad_login(
                _principal("jsmith", GUID_A_TEXT), None, mfa_verified=True
            )
        ).ok
        out = await service._complete_ad_login(_principal("jsmith", None), None, mfa_verified=True)
        assert not out.ok and out.reason == "directory_identity_conflict"
    finally:
        await store.close()


async def test_an_unbound_row_is_never_adopted_by_name() -> None:
    """The decision the ledger row took: NO adopt-and-backfill on first sight.

    Backfilling would leave the recycle window open for every account that had not signed in since
    the column landed -- which is the hole the item exists to close. Section 0: zero deployments, so
    this row cannot occur in the wild today; the rule is what makes the first deployment safe.
    """
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store)
        await store.create_user(
            user_id="legacy-row",
            username="jsmith",
            auth_provider=AuthProvider.AD.value,
            display_name="J Smith",
            email="jsmith@example.org",
        )
        out = await service._complete_ad_login(
            _principal("jsmith", GUID_A_TEXT), None, mfa_verified=True
        )
        assert not out.ok and out.reason == "directory_identity_conflict"
        row = await store.get_user_by_username("jsmith")
        assert row is not None and row.directory_object_id is None, (
            "the refusal backfilled the binding it was supposed to refuse"
        )
    finally:
        await store.close()


async def test_a_directory_that_returns_no_identity_still_resolves_by_name() -> None:
    """The fallback, pinned so it is a decision rather than an accident: with no id on either side
    the behaviour is what shipped before the column existed. The engine cannot key on an identifier
    it is never given."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store)
        first = await service._complete_ad_login(
            _principal("jsmith", None), None, mfa_verified=True
        )
        second = await service._complete_ad_login(
            _principal("jsmith", None), None, mfa_verified=True
        )
        assert first.ok and second.ok
        assert first.identity is not None and second.identity is not None
        assert first.identity.user_id == second.identity.user_id
        assert first.identity.roles == frozenset({Role.OPERATOR})
    finally:
        await store.close()


async def test_a_like_named_local_account_is_still_refused_before_the_identity_check() -> None:
    """Ordering control. The provider-confusion refusal predates this item and must keep its own
    reason, rather than being absorbed into the new one by a check placed above it."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store)
        await service.create_local_user(
            username="jsmith",
            password="Sup3rSecret!!",
            display_name=None,
            email=None,
            roles=[Role.OPERATOR.value],
            actor="test",
        )
        out = await service._complete_ad_login(
            _principal("jsmith", GUID_A_TEXT), None, mfa_verified=True
        )
        assert not out.ok and out.reason != "directory_identity_conflict"
    finally:
        await store.close()


# --- BACKLOG #1532: the id-keyed lookup the session reconciler probes with -------------------------


def test_the_object_guid_filter_carries_the_little_endian_bytes_escaped() -> None:
    """``objectGUID`` has OCTET STRING syntax, so a directory does not answer ``(objectGUID=<text>)``.

    The filter carries the 16 raw bytes, each escaped ``\\hh`` (RFC 4515 section 3). The bytes are
    ``bytes_le`` -- the Microsoft layout :func:`normalise_object_guid` reads back -- so an id that
    round-trips through the store asks about the account it came from. Asserted against the same
    fixture pair the normaliser is tested with, which the test below proves can tell the two byte
    orders apart.
    """
    value = object_guid_filter_value(GUID_A_TEXT)
    assert value is not None
    assert value == "".join("\\%02x" % b for b in GUID_A_BYTES)  # noqa: UP031


def test_the_filter_bytes_normalise_back_to_the_id_they_were_built_from() -> None:
    """The round trip, which is what makes the filter and the stored value the same identity.

    A builder that emitted big-endian bytes would produce a well-formed, WRONG filter: it would
    match nothing, every probe would read ABSENT, and the reconciler would revoke the whole estate
    while looking like a directory outage. ``test_the_fixture_can_tell_the_two_byte_orders_apart``
    is the control that this fixture can see that difference at all.
    """
    value = object_guid_filter_value(GUID_A_TEXT)
    assert value is not None
    raw = bytes(int(pair, 16) for pair in value.split("\\")[1:])
    assert len(raw) == 16
    assert normalise_object_guid(raw) == GUID_A_TEXT


@pytest.mark.parametrize("value", ["", "not-a-guid", "12345678-1234-1234-1234", "   "])
def test_an_unparseable_id_yields_no_filter_rather_than_a_broken_one(value: str) -> None:
    """Refused at the builder, so a value the parser cannot read never reaches a search string.

    This is also why the builder needs no ``_escape_filter`` pass: everything it returns is a
    backslash or a hex digit, produced from 16 validated bytes. Nothing caller-supplied survives.
    """
    assert object_guid_filter_value(value) is None


def test_the_id_keyed_search_asks_the_directory_by_object_guid() -> None:
    """END TO END THROUGH THE REAL LOOKUP, the id-keyed sibling of the search test above.

    Both halves fail independently: a search that filters on the wrong attribute finds nothing, and
    one that filters correctly but drops the id out of the returned mapping leaves the caller unable
    to tell a rename from a match.
    """
    entry = _FakeEntry(
        {
            "sAMAccountName": _FakeAttr("jsmith-married"),
            "objectGUID": _FakeAttr(GUID_A_BRACED, raw=GUID_A_BYTES),
            "displayName": _FakeAttr("J Smith"),
            "mail": _FakeAttr("jsmith@example.org"),
            "userAccountControl": _FakeAttr("512"),
        },
        dn="CN=jsmith,DC=x",
    )
    conn = _FakeConn(entry)
    info = _authenticator()._find_user_by_object_id(conn, GUID_A_TEXT, fallback_username="jsmith")
    assert conn.kwargs["search_filter"] == f"(objectGUID={object_guid_filter_value(GUID_A_TEXT)})"
    assert "objectGUID" in conn.kwargs["attributes"]
    assert info is not None
    assert info["object_id"] == GUID_A_TEXT
    # THE RENAME, carried out of the lookup: the directory's CURRENT name, not the one asked with.
    assert info["username"] == "jsmith-married"


def test_the_id_keyed_search_keeps_the_cached_name_when_the_entry_carries_none() -> None:
    """An absent ``sAMAccountName`` is not the directory announcing a rename to nothing.

    The lookup reports the caller's cached name in that case, so the refresh downstream sees no
    change and writes nothing -- rather than blanking a row's only human-readable label.
    """
    entry = _FakeEntry(
        {
            "objectGUID": _FakeAttr(GUID_A_BRACED, raw=GUID_A_BYTES),
            "userAccountControl": _FakeAttr("512"),
        },
        dn="CN=jsmith,DC=x",
    )
    info = _authenticator()._find_user_by_object_id(
        _FakeConn(entry), GUID_A_TEXT, fallback_username="jsmith"
    )
    assert info is not None and info["username"] == "jsmith"


def test_an_unparseable_stored_id_searches_nothing_rather_than_falling_back_to_a_name() -> None:
    """A search that cannot be built is answered with "no match", never with a different question.

    Falling back to the name here would report on a question the caller did not ask, and the caller
    reads a miss as ABSENT -- which is the revocation path. Refusing to search keeps the two
    distinguishable.
    """
    conn = _FakeConn(_FakeEntry({"sAMAccountName": _FakeAttr("jsmith")}))
    info = _authenticator()._find_user_by_object_id(conn, "not-a-guid", fallback_username="jsmith")
    assert info is None
    assert conn.kwargs == {}, "a malformed id still reached the directory"


def test_the_disabled_account_rejection_covers_the_id_keyed_lookup_too() -> None:
    """ACCOUNTDISABLE (0x2) is checked in the SHARED extraction, so both lookups reject alike.

    If it lived only on the name-keyed path, re-keying the reconciler's probe would have quietly
    stopped a disabled account from being revoked -- trading the security control away to fix the
    availability one.
    """
    entry = _FakeEntry(
        {
            "sAMAccountName": _FakeAttr("jsmith"),
            "objectGUID": _FakeAttr(GUID_A_BRACED, raw=GUID_A_BYTES),
            "userAccountControl": _FakeAttr("514"),  # 512 | 0x2 = ACCOUNTDISABLE
        },
        dn="CN=jsmith,DC=x",
    )
    auth = _authenticator()
    assert (
        auth._find_user_by_object_id(_FakeConn(entry), GUID_A_TEXT, fallback_username="j") is None
    )
    assert auth._find_user(_FakeConn(entry), "jsmith") is None  # the control: same answer both ways


class _RecordingConn:
    """A service connection that records EVERY search, not just the last one.

    ``resolve_principal`` issues two: the user lookup, then the nested-group lookup. A double keeping
    only the last one reports on the group search and reads as though the user search never ran --
    which is the shape of a test that passes while measuring the wrong statement.
    """

    def __init__(self, entry: _FakeEntry) -> None:
        self._entry = entry
        self.entries: list[_FakeEntry] = [entry]
        self.searches: list[dict[str, Any]] = []

    def __enter__(self) -> _RecordingConn:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def search(self, **kwargs: Any) -> None:
        self.searches.append(kwargs)
        # The group search must match nothing, so `_resolve_groups` falls back to the entry's
        # `memberOf` and this double stays a user-lookup instrument rather than a group fixture.
        self.entries = [self._entry] if len(self.searches) == 1 else []


def _recording_authenticator(entry: _FakeEntry) -> tuple[LdapAuthenticator, _RecordingConn]:
    auth = _authenticator()
    conn = _RecordingConn(entry)
    auth._service_conn = lambda: conn  # type: ignore[method-assign]
    return auth, conn


def _live_entry(username: str) -> _FakeEntry:
    return _FakeEntry(
        {
            "sAMAccountName": _FakeAttr(username),
            "objectGUID": _FakeAttr(GUID_A_BRACED, raw=GUID_A_BYTES),
            "displayName": _FakeAttr("J Smith"),
            "mail": _FakeAttr("jsmith@example.org"),
            "memberOf": _FakeAttr(["CN=MF-Ops,DC=x"]),
            "userAccountControl": _FakeAttr("512"),
        },
        dn=f"CN={username},DC=x",
    )


def test_resolve_principal_asks_by_the_immutable_id_when_it_is_given_one() -> None:
    """THE KEY CHOICE, driven through the REAL ``resolve_principal`` rather than through a double.

    **This test exists because a mutation escaped without it.** The key preference used to live in
    ``AuthService._probe_principal``, where the reconciler's tests reach it; moving it down here put
    it behind ``_FakeLdap``, which implements its own preference -- so breaking the engine's copy
    changed nothing any service-level test could see. A double cannot test the thing it replaces.
    """
    auth, conn = _recording_authenticator(_live_entry("jsmith-married"))
    principal = auth.resolve_principal("jsmith", object_id=GUID_A_TEXT)
    assert principal is not None
    assert (
        conn.searches[0]["search_filter"] == f"(objectGUID={object_guid_filter_value(GUID_A_TEXT)})"
    )
    # The rename is carried out: the directory's CURRENT name, not the stale one asked with.
    assert principal.username == "jsmith-married"
    assert principal.directory_object_id == GUID_A_TEXT


def test_resolve_principal_asks_by_name_when_given_no_id() -> None:
    """The other arm of the same choice -- the pair is what discriminates.

    Asserting only the id arm would pass on an implementation that ignored ``username`` entirely, and
    asserting only this one would pass on the pre-#1532 engine. The residual path a directory with no
    readable ``objectGUID`` leaves every account on is exactly this branch.
    """
    auth, conn = _recording_authenticator(_live_entry("jsmith"))
    principal = auth.resolve_principal("jsmith")
    assert principal is not None
    assert conn.searches[0]["search_filter"].startswith("(|(sAMAccountName=jsmith)")
    assert "objectGUID=" not in conn.searches[0]["search_filter"]
