# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Phase-8 PR C3 — AD-group → channel-scope mapping (store + service sync + admin API)."""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import closing
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth.permissions import Role
from messagefoundry.auth.service import AuthService, _allowed_channels
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.store import SCOPE_SOURCE_AD, SCOPE_SOURCE_MANUAL, MessageStore

PW = "Sup3rSecret!!"


# --- store level -------------------------------------------------------------


async def test_scope_map_roundtrip_and_lookup(tmp_path: Path) -> None:
    s = await MessageStore.open(tmp_path / "s.db")
    try:
        await s.set_ad_group_scope_map([("GRP-A", "IB_A"), ("grp-a", "IB_B"), ("grp-all", "*")])
        rows = await s.list_ad_group_scope_map()
        assert {(r["ad_group"], r["channel"]) for r in rows} == {
            ("grp-a", "IB_A"),
            ("grp-a", "IB_B"),
            ("grp-all", "*"),
        }  # ad_group lower-cased, deduped
        assert await s.channels_for_ad_groups(["GRP-A"]) == {"IB_A", "IB_B"}
        assert await s.channels_for_ad_groups(["grp-all"]) == {"*"}
        assert await s.channels_for_ad_groups(["unmapped"]) == set()
    finally:
        await s.close()


async def test_scope_writes_record_their_source(tmp_path: Path) -> None:
    """Every scope write carries its writer, in the same statement (BACKLOG #1927)."""
    s = await MessageStore.open(tmp_path / "src.db")
    try:
        await s.create_user(user_id="u", username="u", auth_provider="ad")
        assert (await s.get_user("u")).channel_scope_source is None  # never written
        await s.set_user_channel_scope("u", json.dumps(["IB_A"]), source=SCOPE_SOURCE_AD)
        got = await s.get_user("u")
        assert (got.channel_scope, got.channel_scope_source) == ('["IB_A"]', SCOPE_SOURCE_AD)
        await s.set_user_channel_scope("u", None, source=SCOPE_SOURCE_MANUAL)
        got = await s.get_user("u")
        assert (got.channel_scope, got.channel_scope_source) == (None, SCOPE_SOURCE_MANUAL)
    finally:
        await s.close()


async def test_the_scope_source_column_upgrade_reruns_clean(tmp_path: Path) -> None:
    """A database opened before BACKLOG #1927 lacks ``channel_scope_source``; the ALTER adds it.

    Driven against a table that really lacks the column, because a fresh open runs the CREATE
    TABLE that already has it and would never reach the guarded ALTER. The existing scope survives
    with NULL provenance, and a second open must not raise ``duplicate column name``."""
    db = tmp_path / "pre-source.db"
    s = await MessageStore.open(str(db))
    try:
        await s.create_user(user_id="u", username="u", auth_provider="ad")
        await s.set_user_channel_scope("u", json.dumps(["IB_A"]), source=SCOPE_SOURCE_MANUAL)
    finally:
        await s.close()
    with closing(sqlite3.connect(db)) as raw:
        raw.execute("ALTER TABLE users DROP COLUMN channel_scope_source")
        raw.commit()
        cols = {r[1] for r in raw.execute("PRAGMA table_info(users)")}
        assert "channel_scope_source" not in cols  # positive control: the column really is gone

    for _ in range(2):
        s = await MessageStore.open(str(db))
        try:
            row = await s.get_user("u")
            assert row is not None and row.channel_scope == '["IB_A"]'
            assert row.channel_scope_source is None  # no backfill: nothing recorded the writer
        finally:
            await s.close()
        # Read the CATALOGUE, not the record: ``from_mapping`` decodes a missing column to None,
        # so the assertion above would still hold if the ALTER were deleted.
        with closing(sqlite3.connect(db)) as raw:
            cols = {r[1] for r in raw.execute("PRAGMA table_info(users)")}
        assert "channel_scope_source" in cols

    s = await MessageStore.open(str(db))
    try:  # and the restored column takes a write, which every AD login now makes
        await s.set_user_channel_scope("u", json.dumps(["IB_B"]), source=SCOPE_SOURCE_AD)
        assert (await s.get_user("u")).channel_scope_source == SCOPE_SOURCE_AD
    finally:
        await s.close()


# --- service sync ------------------------------------------------------------


async def _ad_user(store: MessageStore, username: str) -> object:
    await store.create_user(user_id=username, username=username, auth_provider="ad")
    return await store.get_user(username)


async def test_sync_persists_group_scope_and_audits(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "svc.db")
    try:
        service = AuthService(store, AuthSettings())
        await service.initialize()
        await store.set_ad_group_scope_map([("grp-a", "IB_A"), ("grp-a", "IB_B")])
        user = await _ad_user(store, "ada")

        refreshed = await service._sync_ad_channel_scope(user, frozenset(), ["GRP-A"])
        assert json.loads(refreshed.channel_scope) == ["IB_A", "IB_B"]  # persisted, sorted
        assert any(a["action"] == "auth.ad_scope_resynced" for a in await store.list_audit())
    finally:
        await store.close()


async def test_sync_star_means_all_and_admin_is_untouched(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "svc2.db")
    try:
        service = AuthService(store, AuthSettings())
        await service.initialize()
        await store.set_ad_group_scope_map([("grp-all", "*"), ("grp-a", "IB_A")])

        await _ad_user(store, "eve")
        await store.set_user_channel_scope(
            "eve", json.dumps(["IB_A"]), source=SCOPE_SOURCE_MANUAL
        )  # previously scoped
        scoped = await store.get_user("eve")
        refreshed = await service._sync_ad_channel_scope(scoped, frozenset(), ["grp-all"])
        # BACKLOG #1152: '*' persists the EXPLICIT all-channels grant. It used to persist SQL NULL
        # and lean on NULL meaning "all"; NULL now denies, so that collapse would have inverted a
        # deliberate wildcard mapping into a deny-everything one.
        assert json.loads(refreshed.channel_scope) == ["*"]
        assert _allowed_channels(refreshed, frozenset()) is None  # and it resolves to all channels

        admin = await _ad_user(store, "boss")
        out = await service._sync_ad_channel_scope(
            admin, frozenset({Role.ADMINISTRATOR}), ["grp-a"]
        )
        assert out.channel_scope is None  # admins always all; never scoped
    finally:
        await store.close()


async def test_sync_no_matching_group_leaves_scope_untouched(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "svc3.db")
    try:
        service = AuthService(store, AuthSettings())
        await service.initialize()
        await store.set_ad_group_scope_map([("grp-a", "IB_A")])
        await store.create_user(user_id="u", username="u", auth_provider="ad")
        # A manual per-user scope, set the way an administrator sets one.
        await service.set_channel_scope("u", ["MANUAL"], actor="admin")
        user = await store.get_user("u")
        assert user is not None and user.channel_scope_source == SCOPE_SOURCE_MANUAL
        out = await service._sync_ad_channel_scope(user, frozenset(), ["other-group"])
        assert json.loads(out.channel_scope) == [
            "MANUAL"
        ]  # opt-in: an administrator's scope is untouched when no group matches
    finally:
        await store.close()


# --- BACKLOG #1927: a scope the DIRECTORY granted is withdrawn when no mapped group matches ---


async def test_leaving_the_last_mapped_group_withdraws_the_ad_derived_scope(
    tmp_path: Path,
) -> None:
    """The directory granted the scope, so the directory can take it back.

    Before BACKLOG #1927 a no-match login returned early, so a user removed from their LAST
    scope-mapped group kept the channels an earlier login derived from it, for as long as the
    account existed. The session is the control on the revoke: it must be live before the sync and
    gone after, so a sync that wrote the scope but skipped the revoke fails here."""
    store = await MessageStore.open(tmp_path / "svc4.db")
    try:
        service = AuthService(store, AuthSettings())
        await service.initialize()
        await store.set_ad_group_scope_map([("grp-a", "IB_A")])
        user = await _ad_user(store, "ada")

        granted = await service._sync_ad_channel_scope(user, frozenset(), ["grp-a"])
        assert json.loads(granted.channel_scope) == ["IB_A"]
        assert granted.channel_scope_source == SCOPE_SOURCE_AD
        await _session_for(store, "ada", "h-ada-1927")
        assert await store.list_sessions("ada"), "no session to revoke -- test proves nothing"

        # The directory now reports no mapped group for this user.
        out = await service._sync_ad_channel_scope(granted, frozenset(), ["other-group"])

        assert out.channel_scope is None, "the directory-granted scope survived leaving the group"
        assert _allowed_channels(out, frozenset()) == frozenset()  # and it resolves to a deny
        assert await store.list_sessions("ada") == [], "a stale-scope session is still live"
        rows = [a for a in await store.list_audit() if a["action"] == "auth.ad_scope_resynced"]
        assert len(rows) == 2, "the grant and the withdrawal must each write one audit row"
        # list_audit is newest first, so rows[0] is the withdrawal.
        assert json.loads(rows[0]["detail"]) == {"channels": None, "withdrawn": '["IB_A"]'}
    finally:
        await store.close()


async def test_a_withdrawn_scope_is_not_rewritten_on_the_next_login(tmp_path: Path) -> None:
    """Idempotence: once withdrawn, a second no-match login writes, revokes and audits nothing."""
    store = await MessageStore.open(tmp_path / "svc5.db")
    try:
        service = AuthService(store, AuthSettings())
        await service.initialize()
        await store.set_ad_group_scope_map([("grp-a", "IB_A")])
        user = await _ad_user(store, "ada")
        user = await service._sync_ad_channel_scope(user, frozenset(), ["grp-a"])
        user = await service._sync_ad_channel_scope(user, frozenset(), [])
        assert user.channel_scope is None
        action = "auth.ad_scope_resynced"
        before = len(await store.list_audit(action=action))
        assert before == 2  # the grant and the withdrawal; also keeps clear of the list cap
        await _session_for(store, "ada", "h-ada-1927-b")

        await service._sync_ad_channel_scope(user, frozenset(), [])

        assert len(await store.list_audit(action=action)) == before
        assert await store.list_sessions("ada"), "a no-op sync revoked a session"
    finally:
        await store.close()


async def test_a_scope_with_no_recorded_source_is_withdrawn(tmp_path: Path) -> None:
    """A scope nobody recorded a writer for is treated as the directory's, which fails CLOSED.

    Only a scope marked as an administrator's survives a no-match login. Every writer records its
    source, so an unmarked scope can only be a row written before the column existed; withdrawing
    it denies until an administrator re-grants, rather than keeping a grant nobody can vouch for."""
    store = await MessageStore.open(tmp_path / "svc6.db")
    try:
        service = AuthService(store, AuthSettings())
        await service.initialize()
        await store.set_ad_group_scope_map([("grp-a", "IB_A")])
        await _ad_user(store, "old")
        await store._db.execute(
            "UPDATE users SET channel_scope=?, channel_scope_source=NULL WHERE id=?",
            (json.dumps(["IB_A"]), "old"),
        )
        await store._db.commit()
        user = await store.get_user("old")
        assert user is not None and user.channel_scope is not None  # positive control
        assert user.channel_scope_source is None

        out = await service._sync_ad_channel_scope(user, frozenset(), [])

        assert out.channel_scope is None
    finally:
        await store.close()


async def test_an_admin_scope_set_during_the_login_is_not_withdrawn(tmp_path: Path) -> None:
    """The withdrawal is a compare-and-set, so it cannot overwrite a scope set after the read.

    The login reads the user row, then spends several awaits before the scope sync. An
    administrator who sets a scope in that window must keep it. Passing the STALE record, read
    before the administrator's write, reproduces the window deterministically."""
    store = await MessageStore.open(tmp_path / "svc9.db")
    try:
        service = AuthService(store, AuthSettings())
        await service.initialize()
        await store.set_ad_group_scope_map([("grp-a", "IB_A")])
        await _ad_user(store, "ada")
        stale = await service._sync_ad_channel_scope(
            await store.get_user("ada"), frozenset(), ["grp-a"]
        )
        assert stale.channel_scope_source == SCOPE_SOURCE_AD  # what the login read

        await service.set_channel_scope("ada", ["MANUAL"], actor="admin")  # lands mid-login
        await _session_for(store, "ada", "h-ada-1927-d")

        out = await service._sync_ad_channel_scope(stale, frozenset(), [])

        assert json.loads(out.channel_scope) == ["MANUAL"], "the withdrawal overwrote the admin"
        assert out.channel_scope_source == SCOPE_SOURCE_MANUAL
        assert await store.list_sessions("ada"), "a withdrawal that did not happen revoked"
    finally:
        await store.close()


async def test_the_withdrawal_is_bound_to_the_scope_it_was_decided_on(tmp_path: Path) -> None:
    """A concurrent login's fresh directory grant is not withdrawn by a login that read the old one.

    Login A reads ``["IB_A"]`` and finds no mapped group. Before A writes, login B finds the user in
    a mapped group and writes ``["IB_B"]``, also marked ``"ad"``. A's withdrawal must miss, because
    the value it decided on is gone."""
    store = await MessageStore.open(tmp_path / "svc11.db")
    try:
        service = AuthService(store, AuthSettings())
        await service.initialize()
        await store.set_ad_group_scope_map([("grp-a", "IB_A"), ("grp-b", "IB_B")])
        await _ad_user(store, "ada")
        stale = await service._sync_ad_channel_scope(
            await store.get_user("ada"), frozenset(), ["grp-a"]
        )
        await service._sync_ad_channel_scope(stale, frozenset(), ["grp-b"])  # login B

        out = await service._sync_ad_channel_scope(stale, frozenset(), [])  # login A, late

        assert json.loads(out.channel_scope) == ["IB_B"], "a stale login withdrew a fresh grant"
    finally:
        await store.close()


async def test_a_scope_that_already_denies_is_left_alone(tmp_path: Path) -> None:
    """An unmarked ``[]`` already denies, so a no-match login rewrites nothing and revokes nothing.

    Rewriting it to NULL would change no decision, erase the "somebody chose this" meaning that
    ``[]`` carries over NULL, and sign the user out of every other session for no reason."""
    store = await MessageStore.open(tmp_path / "svc10.db")
    try:
        service = AuthService(store, AuthSettings())
        await service.initialize()
        await _ad_user(store, "old")
        await store._db.execute(
            "UPDATE users SET channel_scope='[]', channel_scope_source=NULL WHERE id=?", ("old",)
        )
        await store._db.commit()
        await _session_for(store, "old", "h-old-1927")
        user = await store.get_user("old")
        assert user is not None and user.channel_scope == "[]"  # positive control

        out = await service._sync_ad_channel_scope(user, frozenset(), [])

        assert out.channel_scope == "[]"
        assert await store.list_sessions("old")
        assert await store.list_audit(action="auth.ad_scope_resynced") == []
    finally:
        await store.close()


async def test_a_directory_grant_replaces_a_manual_scope_and_is_then_withdrawable(
    tmp_path: Path,
) -> None:
    """A matching group still overrides a manual scope, as it always did, and takes its provenance.

    This pins the existing half of the rule: the directory is authoritative whenever a mapped group
    matches. Once it has written the scope the scope is the directory's, so leaving the group then
    withdraws it rather than restoring the administrator's earlier value."""
    store = await MessageStore.open(tmp_path / "svc7.db")
    try:
        service = AuthService(store, AuthSettings())
        await service.initialize()
        await store.set_ad_group_scope_map([("grp-a", "IB_A")])
        await _ad_user(store, "ada")
        await service.set_channel_scope("ada", ["MANUAL"], actor="admin")
        user = await store.get_user("ada")
        assert user is not None

        user = await service._sync_ad_channel_scope(user, frozenset(), ["grp-a"])
        assert json.loads(user.channel_scope) == ["IB_A"]
        assert user.channel_scope_source == SCOPE_SOURCE_AD

        user = await service._sync_ad_channel_scope(user, frozenset(), [])
        assert user.channel_scope is None
    finally:
        await store.close()


async def test_an_identical_manual_scope_is_taken_over_without_a_revoke(tmp_path: Path) -> None:
    """A matching group whose scope equals an administrator's takes provenance and revokes nothing.

    The effective scope does not change, so no live session holds a stale grant. The write is still
    audited, because it changes whether a later group removal will withdraw the scope."""
    store = await MessageStore.open(tmp_path / "svc8.db")
    try:
        service = AuthService(store, AuthSettings())
        await service.initialize()
        await store.set_ad_group_scope_map([("grp-a", "IB_A")])
        await _ad_user(store, "ada")
        await service.set_channel_scope("ada", ["IB_A"], actor="admin")
        user = await store.get_user("ada")
        assert user is not None and user.channel_scope_source == SCOPE_SOURCE_MANUAL
        await _session_for(store, "ada", "h-ada-1927-c")

        out = await service._sync_ad_channel_scope(user, frozenset(), ["grp-a"])

        assert out.channel_scope_source == SCOPE_SOURCE_AD
        assert json.loads(out.channel_scope) == ["IB_A"]
        assert await store.list_sessions("ada"), "an unchanged scope revoked a live session"
        assert any(a["action"] == "auth.ad_scope_resynced" for a in await store.list_audit())
    finally:
        await store.close()


# --- admin API ---------------------------------------------------------------


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "api.db", poll_interval=0.02)
    yield eng
    await eng.stop()


async def _admin_service(engine: Engine) -> AuthService:
    """An auth service holding one usable local administrator, ``boss``.

    Step-up admin endpoint tests, not MFA tests: ``require_mfa=False`` so the admin's PUT isn't
    blocked first by the BACKLOG #187 secure default (require_mfa now ON)."""
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    boss_id = await service.create_local_user(
        username="boss",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.ADMINISTRATOR.value],
        actor="test",
    )
    # Admin-created accounts force first-login rotation (WP-L3-12); clear it (keep the same hash).
    boss = await service.store.get_user(boss_id)
    assert boss is not None and boss.password_hash is not None
    await service.store.set_password(
        boss_id, password_hash=boss.password_hash, must_change_password=False
    )
    return service


async def _boss_headers(c: httpx.AsyncClient) -> dict[str, str]:
    body = {"username": "boss", "password": PW, "provider": "local"}
    tok = (await c.post("/auth/login", json=body)).json()["token"]
    return {"Authorization": f"Bearer {tok}"}


async def test_the_users_list_shows_who_wrote_each_scope(engine: Engine) -> None:
    """BACKLOG #1958: ``GET /users`` carries ``channel_scope_source`` beside each scope.

    Without it an administrator cannot see that a scope is the directory's, so nothing warns them
    that saving it makes it manual. This also pins what that save does today: an administrator's
    PUT of the SAME directory scope marks it manual, and a later sign-in that matches no mapped
    group then keeps it. The console's warning exists because of that second half."""
    service = await _admin_service(engine)
    await engine.store.set_ad_group_scope_map([("grp-a", "IB_A")])
    # Hex ids, because the JSON route takes a ResourceId in its path.
    ada_id, len_id = uuid.uuid4().hex, uuid.uuid4().hex
    await engine.store.create_user(user_id=ada_id, username="ada", auth_provider="ad")
    await engine.store.create_user(user_id=len_id, username="len", auth_provider="local")
    ada = await service._sync_ad_channel_scope(
        await engine.store.get_user(ada_id), frozenset(), ["grp-a"]
    )
    assert ada.channel_scope_source == SCOPE_SOURCE_AD  # positive control on the setup

    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _boss_headers(c)

        async def sources() -> dict[str, tuple[object, object]]:
            users = (await c.get("/users", headers=h)).json()
            return {u["username"]: (u["channel_scope"], u["channel_scope_source"]) for u in users}

        got = await sources()
        assert got["ada"] == (["IB_A"], "ad")
        assert got["len"] == (None, None)  # no scope writer has run

        # The re-save: the same scope, unchanged, through the admin API.
        r = await c.put(f"/users/{ada_id}/channel-scope", json={"channels": ["IB_A"]}, headers=h)
        assert r.status_code == 200
        assert (await sources())["ada"] == (["IB_A"], "manual")

    # And manual is what keeps it: leaving the last mapped group no longer withdraws it.
    user = await engine.store.get_user(ada_id)
    assert user is not None
    out = await service._sync_ad_channel_scope(user, frozenset(), [])
    assert json.loads(out.channel_scope) == ["IB_A"]


async def test_ad_group_scope_map_admin_endpoint(engine: Engine) -> None:
    service = await _admin_service(engine)
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _boss_headers(c)
        assert (await c.get("/ad-group-scope-map", headers=h)).json()["entries"] == []
        body = {"entries": [{"ad_group": "Lab-Ops", "channel": "IB_LAB"}]}
        assert (await c.put("/ad-group-scope-map", json=body, headers=h)).status_code == 200
        got = (await c.get("/ad-group-scope-map", headers=h)).json()["entries"]
        assert got == [{"ad_group": "lab-ops", "channel": "IB_LAB"}]  # lower-cased group
        assert any(
            a["action"] == "ad_group_scope_map.updated" for a in await engine.store.list_audit()
        )


# --- BACKLOG #1154 (ASVS 8.3.2): a map edit must apply immediately -----------


async def _session_for(store: MessageStore, user_id: str, token: str) -> None:
    """Give ``user_id`` one live session. Uses the store directly so the test does not depend on a
    working directory bind, which is what the login path would need for an AD account."""
    await store.create_session(
        token_hash=token, user_id=user_id, expires_at=time.time() + 3600, client="pytest"
    )


@pytest.mark.parametrize(
    ("setter", "action", "entry"),
    [
        # The two maps take DIFFERENT right-hand values -- a role id and a channel name -- and the
        # role map has a foreign key onto the roles table, so a channel here fails the constraint
        # rather than the assertion. Parametrised so each setter gets a value it will accept.
        ("set_ad_group_map", "ad_group_map.updated", (Role.OPERATOR.value)),
        ("set_ad_group_scope_map", "ad_group_scope_map.updated", "IB_A"),
    ],
)
async def test_editing_an_ad_map_revokes_directory_sessions(
    tmp_path: Path, setter: str, action: str, entry: str
) -> None:
    """Both AD map setters are authorization-value mutators, so both must revoke.

    The group maps resolve to role sets and to channel scope, which is what an authorization
    decision reads. Before BACKLOG #1154 neither setter revoked anything, so an edit did not reach a
    session already running -- it waited for that principal's next login. Every sibling mutator
    (`set_roles`, `set_channel_scope`, disable, password reset) already revoked.

    The LOCAL account is the control, and it is the half that makes this test mean something: a
    revoke-everything implementation would satisfy the AD assertion just as well, and this is what
    tells the two apart. Neither map is read for a local account, so its session must survive.
    """
    store = await MessageStore.open(tmp_path / f"{setter}.db")
    try:
        service = AuthService(store, AuthSettings())
        await service.initialize()

        await store.create_user(user_id="ada", username="ada", auth_provider="ad")
        await store.create_user(user_id="len", username="len", auth_provider="local")
        await _session_for(store, "ada", f"h-ada-{setter}")
        await _session_for(store, "len", f"h-len-{setter}")
        # Liveness receipt: assert the precondition rather than assuming it. If session creation
        # silently no-opped, every assertion below would pass on an empty table.
        assert await store.list_sessions("ada"), "no AD session to revoke -- test proves nothing"
        assert await store.list_sessions("len"), "no local session -- the control is not armed"

        await getattr(service, setter)([("grp-a", entry)], actor="admin")

        assert await store.list_sessions("ada") == [], (
            f"{setter} left a directory session running on the pre-edit mapping"
        )
        assert await store.list_sessions("len"), (
            f"{setter} revoked a LOCAL account's session; neither AD map is read for a local user"
        )

        rows = [a for a in await store.list_audit() if a["action"] == action]
        assert len(rows) == 1, f"expected one {action} audit row, got {len(rows)}"
        assert json.loads(rows[0]["detail"])["sessions_revoked"] == 1, (
            "the audit row must record how many sessions the edit revoked, so an operator can see "
            "the blast radius of a map change without reconstructing it"
        )
    finally:
        await store.close()
