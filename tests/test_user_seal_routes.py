# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5520: the admin user reads serve only an account record that passes its seal.

``GET /users``, ``GET /users/{id}/federated-identity``, ``GET /users/{id}/channel-scope`` and
``GET /users/{id}/permissions`` read through :meth:`AuthService.checked_user` and
:meth:`AuthService.list_checked_users`, so a row altered outside the store is never served with a
200, and its failure is handed to the seal-failure report, whose first report in each interval
writes the ``integrity.authority_seal_failed`` row and raises the alert. The list keeps such an
account by id alone (:class:`IntegrityFailedUser`); each single-account read, and
``PATCH /users/{id}``, answers 423. Each test has a control: the same read of an intact account,
and of an unknown id, which stays a 404. A check that races a write while the row is read is
unreported and read again; a row still there after every check raced fails closed, a reported 423,
and only a row absent on a re-read is gone.
"""

from __future__ import annotations

import dataclasses
import itertools
import re
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.api.auth_models import IntegrityFailedUser, UserListEntry, UserSummary
from messagefoundry.auth import Role
from messagefoundry.auth.service import (
    _CHECKED_READ_PASSES,
    AUTHORITY_SEAL_FAILED_ACTION,
    USER_SEAL_REFUSED,
    AuthService,
    UserSealRefused,
)
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.store import AdminRemoval, MessageStore, UserRecord
from tests.test_api_auth import ABSENT_USER_ID, _add, _auth, _login, _reauth
from tests.test_user_seal import _raw_for

#: What the tampering writes. None of it may appear in an answer.
_PLANTED = "planted-outside-the-store"


@pytest.fixture
async def keyed(tmp_path: Path) -> AsyncIterator[tuple[Engine, Path]]:
    path = tmp_path / "sealed_routes.db"
    store = await MessageStore.open(path, cipher=make_cipher(generate_key(), write_v2=True))
    engine = Engine(
        store, poll_interval=0.02, egress_settings=EgressSettings(deny_by_default=False)
    )
    try:
        yield engine, path
    finally:
        await engine.stop()


async def _tamper(path: Path, user_id: str) -> None:
    """Alter the account's sealed fields on a connection that holds no store key."""
    await _raw_for(path)(
        "UPDATE users SET display_name=?, channel_scope=?, oidc_issuer=?, oidc_subject=? WHERE id=?",
        (_PLANTED, f'["{_PLANTED}"]', _PLANTED, _PLANTED, user_id),
    )


async def _setup(engine: Engine, **settings: Any) -> tuple[AuthService, list[str], str, str]:
    """An administrator, an intact viewer and a viewer whose row is then tampered with.
    ``settings`` adds to the service's :class:`AuthSettings`."""
    alerts: list[str] = []
    service = AuthService(
        engine.store,
        AuthSettings(admin_write_min_interval_seconds=0, require_mfa=False, **settings),
        integrity_alert=alerts.append,
    )
    await service.initialize()
    await _add(service, "root", Role.ADMINISTRATOR)
    intact = await _add(service, "intact", Role.VIEWER)
    victim = await _add(service, "victim", Role.VIEWER)
    return service, alerts, intact, victim


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(engine, auth=service), client=("127.0.0.1", 1))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def _seal_failures(engine: Engine, user_id: str) -> int:
    rows = await engine.store.list_audit(action=AUTHORITY_SEAL_FAILED_ACTION, limit=10_000)
    return sum(1 for row in rows if user_id in str(row["detail"]))


async def test_get_users_lists_a_failing_account_by_id_alone(keyed: tuple[Engine, Path]) -> None:
    engine, path = keyed
    service, alerts, intact, victim = await _setup(engine)
    async with _client(engine, service) as c:
        token = (await _login(c, "root")).json()["token"]
        before = await c.get("/users", headers=_auth(token))
        assert before.status_code == 200
        # Control: before the tampering every row is a full summary.
        assert all("username" in row for row in before.json())
        await _tamper(path, victim)
        resp = await c.get("/users", headers=_auth(token))
    assert resp.status_code == 200
    assert _PLANTED not in resp.text
    rows = {row["id"]: row for row in resp.json()}
    # The pinned shape: the id and the flag, and nothing else of the row.
    assert rows[victim] == {"id": victim, "integrity_failed": True}
    # The intact account is untouched, its roles read from the checked record.
    assert rows[intact]["username"] == "intact"
    assert rows[intact]["roles"] == [Role.VIEWER.value]
    assert "integrity_failed" not in rows[intact]
    assert await _seal_failures(engine, victim) >= 1
    assert any(victim in alert for alert in alerts)


@pytest.mark.parametrize("suffix", ["federated-identity", "channel-scope", "permissions"])
async def test_a_single_account_read_answers_423_for_a_failing_record(
    keyed: tuple[Engine, Path], suffix: str
) -> None:
    engine, path = keyed
    service, alerts, intact, victim = await _setup(engine)
    await _tamper(path, victim)
    async with _client(engine, service) as c:
        token = (await _login(c, "root")).json()["token"]
        refused = await c.get(f"/users/{victim}/{suffix}", headers=_auth(token))
        served = await c.get(f"/users/{intact}/{suffix}", headers=_auth(token))
        absent = await c.get(f"/users/{ABSENT_USER_ID}/{suffix}", headers=_auth(token))
    assert refused.status_code == 423, refused.text
    assert refused.json()["detail"] == USER_SEAL_REFUSED
    assert _PLANTED not in refused.text
    assert await _seal_failures(engine, victim) >= 1
    assert any(victim in alert for alert in alerts)
    # Controls: an intact account is served, and an unknown one is still a 404.
    assert served.status_code == 200
    assert absent.status_code == 404


async def test_the_permissions_read_lists_the_checked_roles(keyed: tuple[Engine, Path]) -> None:
    """The role ids come from the record the seal covered, not a second, unchecked store read."""
    engine, _ = keyed
    service, _alerts, intact, _victim = await _setup(engine)

    async def no_bare_role_read(user_id: str) -> list[str]:
        raise AssertionError("the bare role-id reader was called")

    engine.store.get_user_role_ids = no_bare_role_read  # type: ignore[method-assign]
    async with _client(engine, service) as c:
        token = (await _login(c, "root")).json()["token"]
        resp = await c.get(f"/users/{intact}/permissions", headers=_auth(token))
        listed = await c.get("/users", headers=_auth(token))
    assert resp.status_code == 200 and resp.json()["roles"] == [Role.VIEWER.value]
    assert listed.status_code == 200


async def test_patch_answers_423_for_a_failing_record(keyed: tuple[Engine, Path]) -> None:
    engine, path = keyed
    service, _alerts, intact, victim = await _setup(engine)
    await _tamper(path, victim)
    async with _client(engine, service) as c:
        token = (await _login(c, "root")).json()["token"]
        _, token = await _reauth(c, token, purpose="admin_user_update")
        refused = await c.patch(
            f"/users/{victim}", json={"display_name": "x"}, headers=_auth(token)
        )
        _, token = await _reauth(c, token, purpose="admin_user_update")
        absent = await c.patch(
            f"/users/{ABSENT_USER_ID}", json={"display_name": "x"}, headers=_auth(token)
        )
        _, token = await _reauth(c, token, purpose="admin_user_update")
        served = await c.patch(f"/users/{intact}", json={"display_name": "x"}, headers=_auth(token))
    assert refused.status_code == 423, refused.text
    assert _PLANTED not in refused.text
    assert absent.status_code == 404
    assert served.status_code == 200, served.text
    assert await _seal_failures(engine, victim) >= 1


async def test_checked_user_tells_a_failing_record_from_a_missing_one(
    keyed: tuple[Engine, Path],
) -> None:
    engine, path = keyed
    service, _alerts, intact, victim = await _setup(engine)
    await _tamper(path, victim)
    checked = await service.checked_user(intact)
    assert checked is not None and checked.role_ids == (Role.VIEWER.value,)
    assert await service.checked_user(ABSENT_USER_ID) is None
    with pytest.raises(UserSealRefused):
        await service.checked_user(victim)
    listed = {entry.id: entry.user for entry in await service.list_checked_users()}
    assert listed[victim] is None and listed[intact] is not None


async def test_a_listed_account_deleted_mid_read_is_left_out(keyed: tuple[Engine, Path]) -> None:
    """A row the list read that is gone by its re-read is not an integrity failure."""
    engine, _ = keyed
    service, _alerts, _intact, victim = await _setup(engine)
    original = engine.store.list_users

    async def list_then_delete() -> list[object]:
        rows = await original()
        await engine.store.remove_unless_last_admin(
            victim, AdminRemoval.DELETE, admin_role_id=Role.ADMINISTRATOR.value, audits=()
        )
        return list(rows)

    engine.store.list_users = list_then_delete  # type: ignore[method-assign,assignment]
    listed = await service.list_checked_users()
    assert victim not in {entry.id for entry in listed}
    assert await _seal_failures(engine, victim) == 0


def test_a_user_list_entry_reads_either_shape_and_never_the_other() -> None:
    """The pinned wire shape: a summary payload never reads as a failed row, and a failed row,
    which carries no name, provider, flag or roles, never reads as a summary."""
    from pydantic import TypeAdapter

    entry: TypeAdapter[UserListEntry] = TypeAdapter(UserListEntry)
    summary = entry.validate_python(
        {
            "id": "a",
            "username": "a",
            "auth_provider": "local",
            "disabled": False,
            "roles": [],
            "channel_scope_withheld": True,
        }
    )
    assert isinstance(summary, UserSummary)
    failed = entry.validate_python({"id": "b", "integrity_failed": True})
    assert isinstance(failed, IntegrityFailedUser)
    assert IntegrityFailedUser.model_fields.keys() == {"id", "integrity_failed"}
    with pytest.raises(ValueError):
        IntegrityFailedUser.model_validate({"id": "c"})


def _empty_grants(engine: Engine, user_id: str, *, times: int | None = None) -> list[int]:
    """Make ``user_id``'s role rows read as empty, so its record fails its seal on every check, or
    on the first ``times`` reads only. The returned list counts the reads it emptied."""
    store = engine.store
    real_grants = store.get_user_role_grants
    emptied: list[int] = []

    async def no_grants(uid: str) -> list[object]:
        if uid == user_id and (times is None or len(emptied) < times):
            emptied.append(1)
            return []
        return list(await real_grants(uid))

    store.get_user_role_grants = no_grants  # type: ignore[method-assign,assignment]
    return emptied


def _rekey_every_read(
    engine: Engine, user_id: str, *, delete_on_read: int | None = None, times: int | None = None
) -> list[int]:
    """Make every row read of ``user_id`` by id return the account under new keys, its username and
    its federated subject, as a writer with direct database access that keeps flipping them would,
    so each check of a failing record races; or only the first ``times`` reads. With
    ``delete_on_read``, that read deletes the row for real before it answers, so every later read
    finds nothing. The returned list holds the number of each read it re-keyed."""
    store = engine.store
    real_get_user = store.get_user
    reads = itertools.count(1)
    rekeyed_reads: list[int] = []

    async def rekeyed(uid: str) -> UserRecord | None:
        row = await real_get_user(uid)
        if row is None or uid != user_id or (times is not None and len(rekeyed_reads) >= times):
            return row
        read = next(reads)
        rekeyed_reads.append(read)
        if read == delete_on_read:
            await store.remove_unless_last_admin(
                user_id, AdminRemoval.DELETE, admin_role_id=Role.ADMINISTRATOR.value, audits=()
            )
        return dataclasses.replace(
            row, username=f"{row.username}-{read}", oidc_subject=f"flipped-{read}"
        )

    store.get_user = rekeyed  # type: ignore[method-assign,assignment]
    return rekeyed_reads


@pytest.mark.parametrize("suffix", ["federated-identity", "channel-scope", "permissions"])
async def test_a_failing_row_whose_keys_flip_on_every_read_fails_closed(
    keyed: tuple[Engine, Path], suffix: str
) -> None:
    """BACKLOG #5520: a check that races a re-key is unreported, and is read again. A tampered row
    whose keys flip on every read races every pass; it used to read as gone, a 404 and missing from
    ``GET /users`` with no report, so a writer with direct database access could hide it. It now
    fails closed: 423, listed as failed, and reported."""
    engine, path = keyed
    service, alerts, _intact, victim = await _setup(engine)
    await _tamper(path, victim)
    async with _client(engine, service) as c:
        token = (await _login(c, "root")).json()["token"]
        _rekey_every_read(engine, victim)
        refused = await c.get(f"/users/{victim}/{suffix}", headers=_auth(token))
        listed = await c.get("/users", headers=_auth(token))
    assert refused.status_code == 423, refused.text
    assert refused.json()["detail"] == USER_SEAL_REFUSED
    assert _PLANTED not in refused.text
    assert listed.status_code == 200
    assert {"id": victim, "integrity_failed": True} in listed.json()
    assert await _seal_failures(engine, victim) == 1
    assert any(victim in alert for alert in alerts)


async def test_a_fail_closed_refusal_is_reported_under_the_stored_id(
    keyed: tuple[Engine, Path],
) -> None:
    """On a store that finds an id case-insensitively, as SQL Server's default collation does, the
    fail-closed report is keyed by the id the row holds, not the caller's spelling of it, so a
    second spelling inside the interval adds no second row."""
    engine, path = keyed
    service, _alerts, _intact, victim = await _setup(engine)
    await _tamper(path, victim)
    store = engine.store
    real_get_user = store.get_user
    reads = itertools.count(1)

    async def any_case_rekeyed(uid: str) -> UserRecord | None:
        row = await real_get_user(uid.lower())
        if row is None or row.id != victim:
            return row
        read = next(reads)
        return dataclasses.replace(row, username=f"{row.username}-{read}")

    store.get_user = any_case_rekeyed  # type: ignore[method-assign,assignment]
    for spelling in (victim.upper(), victim.swapcase(), victim):
        with pytest.raises(UserSealRefused):
            await service.checked_user(spelling)
    assert victim.upper() != victim
    rows = await engine.store.list_audit(action=AUTHORITY_SEAL_FAILED_ACTION, limit=10_000)
    named = [str(row["detail"]) for row in rows if victim in str(row["detail"]).lower()]
    assert len(named) == 1 and victim in named[0], named


async def test_a_row_deleted_after_every_pass_raced_is_still_gone(
    keyed: tuple[Engine, Path],
) -> None:
    """The control for the fail-closed test: the same flipping keys, but the row is deleted by the
    last re-read of the last pass, so the existence read after the passes finds nothing. Only a row
    that is still there fails closed; this one is a 404, unreported."""
    engine, path = keyed
    service, alerts, _intact, victim = await _setup(engine)
    await _tamper(path, victim)
    async with _client(engine, service) as c:
        token = (await _login(c, "root")).json()["token"]
        # Each pass reads the row by id twice: its own read, and _verified's re-read.
        _rekey_every_read(engine, victim, delete_on_read=2 * _CHECKED_READ_PASSES)
        gone = await c.get(f"/users/{victim}/channel-scope", headers=_auth(token))
    assert gone.status_code == 404, gone.text
    assert await _seal_failures(engine, victim) == 0
    assert not any(victim in alert for alert in alerts)


async def test_one_raced_pass_then_a_passing_read_is_served(keyed: tuple[Engine, Path]) -> None:
    """A single race is still unreported: an intact account whose first check reads empty role
    rows under keys its re-read no longer finds, as an honest rename committing between the reads
    would, is read again by id and served."""
    engine, _ = keyed
    service, alerts, intact, _victim = await _setup(engine)
    async with _client(engine, service) as c:
        token = (await _login(c, "root")).json()["token"]
        emptied = _empty_grants(engine, intact, times=1)
        # The first pass's own read is re-keyed, so _verified's re-read finds other keys.
        rekeyed = _rekey_every_read(engine, intact, times=1)
        served = await c.get(f"/users/{intact}/channel-scope", headers=_auth(token))
    assert (len(emptied), len(rekeyed)) == (1, 1)
    assert served.status_code == 200, served.text
    assert await _seal_failures(engine, intact) == 0
    assert not any(intact in alert for alert in alerts)


async def test_a_race_free_failure_of_the_same_shape_is_a_reported_423(
    keyed: tuple[Engine, Path],
) -> None:
    """A failure with no re-key between the reads: empty role rows read twice under the same keys
    are an established failure, answered 423 and listed as failed, and reported."""
    engine, _ = keyed
    service, alerts, _intact, victim = await _setup(engine)
    async with _client(engine, service) as c:
        token = (await _login(c, "root")).json()["token"]
        _empty_grants(engine, victim)
        refused = await c.get(f"/users/{victim}/channel-scope", headers=_auth(token))
        listed = await c.get("/users", headers=_auth(token))
    assert refused.status_code == 423, refused.text
    assert {"id": victim, "integrity_failed": True} in listed.json()
    assert await _seal_failures(engine, victim) == 1
    assert any(victim in alert for alert in alerts)


async def test_a_refusal_inside_the_report_interval_adds_no_row(
    keyed: tuple[Engine, Path],
) -> None:
    """What docs/SECURITY.md, *What an admin user read reports*, states: the report is rate-limited
    per account, so a second 423 inside the interval writes no second row. The 423 still stands,
    because the failure itself was established."""
    engine, path = keyed
    service, alerts, _intact, victim = await _setup(engine)
    await _tamper(path, victim)
    async with _client(engine, service) as c:
        token = (await _login(c, "root")).json()["token"]
        first = await c.get(f"/users/{victim}/channel-scope", headers=_auth(token))
        second = await c.get(f"/users/{victim}/permissions", headers=_auth(token))
    assert first.status_code == second.status_code == 423
    assert await _seal_failures(engine, victim) == 1
    assert sum(victim in alert for alert in alerts) == 1


async def test_patch_spends_its_grant_on_a_423(keyed: tuple[Engine, Path]) -> None:
    """The cost docs/SECURITY.md states: the gate spends the single-use ``admin_user_update`` grant
    before the route reads the account, so a 423 leaves none. The next PATCH, of an intact account,
    is refused for the step-up; the control re-authenticates and is served."""
    engine, path = keyed
    service, _alerts, intact, victim = await _setup(engine)
    await _tamper(path, victim)
    async with _client(engine, service) as c:
        token = (await _login(c, "root")).json()["token"]
        _, token = await _reauth(c, token, purpose="admin_user_update")
        refused = await c.patch(
            f"/users/{victim}", json={"display_name": "x"}, headers=_auth(token)
        )
        spent = await c.patch(f"/users/{intact}", json={"display_name": "x"}, headers=_auth(token))
        _, token = await _reauth(c, token, purpose="admin_user_update")
        served = await c.patch(f"/users/{intact}", json={"display_name": "x"}, headers=_auth(token))
    assert refused.status_code == 423, refused.text
    assert spent.status_code == 403, spent.text
    assert spent.headers.get("X-Step-Up-Action") == "admin_user_update"
    assert served.status_code == 200, served.text


async def test_patch_spends_nothing_on_a_423_when_action_binding_is_off(
    keyed: tuple[Engine, Path],
) -> None:
    """The condition docs/SECURITY.md states: with ``[auth].require_action_step_up`` off the gate
    checks the session window and spends no grant, so a 423 costs nothing, and the next PATCH, of
    an intact account, is served inside the same window with no new proof."""
    engine, path = keyed
    service, _alerts, intact, victim = await _setup(engine, require_action_step_up=False)
    await _tamper(path, victim)
    async with _client(engine, service) as c:
        token = (await _login(c, "root")).json()["token"]
        _, token = await _reauth(c, token)
        refused = await c.patch(
            f"/users/{victim}", json={"display_name": "x"}, headers=_auth(token)
        )
        served = await c.patch(f"/users/{intact}", json={"display_name": "x"}, headers=_auth(token))
    assert refused.status_code == 423, refused.text
    assert served.status_code == 200, served.text


_SECURITY_MD = Path(__file__).resolve().parents[1] / "docs" / "SECURITY.md"
_STATEMENT = "**What an admin user read reports (BACKLOG #5520).**"


def test_the_security_doc_states_what_a_423_reports_and_costs() -> None:
    """docs/SECURITY.md states the rate-limited report, the race and the PATCH grant cost once, and
    every route row that answers for a failing record points at that statement rather than
    claiming an audit row and an alert of its own."""
    text = _SECURITY_MD.read_text("utf-8")
    assert text.count(_STATEMENT) == 1
    body = " ".join(text.split(_STATEMENT, 1)[1].split("\n\n", 1)[0].split())
    for fact in (
        "`SEAL_FAILURE_REPORT_INTERVAL_SECONDS`",
        "only the first refusal under a report key in each report interval",
        "writes no `integrity.authority_seal_failed` row and raises no alert",
        "one absent on a re-read reads as gone",
        "A row still there after every check raced fails closed",
        "One that keeps changing the row's own `id` still can",
        "`SEAL_FAILURE_TRACK_MAX`",
        "Two honest role writes to the account that commit across both of those reads",
        "Each engine process sharing the store keeps its own interval",
        "Where `[auth].require_action_step_up` is on, the default",
        "the single-use `admin_user_update` grant, so its 423 and its 404 cost that proof",
        "Where it is off, the gate checks the step-up session window instead and spends nothing",
    ):
        assert fact in body, fact
    rows = [line for line in text.splitlines() if line.startswith("|") and "#5520" in line]
    assert len(rows) == 5, rows
    for row in rows:
        assert "*What an admin user read reports* below this table" in row, row
        assert "audit row and alert" not in row and "audited and alerted" not in row, row


#: The console sentences this PR's code change needs in that statement (Lander hold 7090810151):
#: the users list links a failing account's delete, for a ``users:manage`` holder only, to the
#: confirmation page, which shows a page in place of the 423 its checked read answers for that
#: record, inside the report interval or not and for a record Vault transit cannot verify too; and
#: the post-action pages' fallback is stated once, in ``_shown_name``'s docstring, which this
#: statement points at. Lander hold 7091484059 added the two answer sentences the confirmation
#: made false, which are not console sentences, and the page's own-account case.
#: Case-insensitive regexes over the whitespace-normalised statement.
_CONSOLE_SENTENCES = {
    "the list's delete is the confirmation's, for users:manage": (
        r"to a caller holding `users:manage` it links that account's delete to "
        r"`GET /ui/users/\{user_id\}/delete-confirm`"
    ),
    "the confirmation answers a refused record rather than the 423": (
        r"delete-confirm`, which, for a record its checked read refuses with 423, shows a "
        r"confirmation naming the id alone rather than the 423 this paragraph gives a failing "
        r"record"
    ),
    "the post-action fallback points at _shown_name": (
        r"rather than answering 423\. What those pages show and log when that read fails is "
        r"stated in the docstring of `_shown_name`"
    ),
    # Lander hold 7091484059: the confirmation catches the 423 and answers 200, so the two
    # sentences that said every refusal answers 423 or is listed as failed were narrowed, and the
    # page's own-account case is stated. Lander hold 7095706239: the interval sentence names the
    # confirmation beside its deferral, the Vault transit one says the record is refused at its
    # first check, and the report key is the part and the id.
    "the interval sentence defers to the per-route answers": (
        r"gets the answer its reader gives a failing record, which is not a 423 at least for "
        r"`GET /ui/users/\{user_id\}/delete-confirm`"
    ),
    "the Vault transit sentence says the record is refused at its first check": (
        r"a record Vault transit cannot verify is refused at the first check that cannot verify "
        r"it, with no re-read, rather than after two failing reads, and then gets the answer its "
        r"reader gives a failing record\. It is reported under "
        r"`integrity\.authority_seal_unverifiable`"
    ),
    "the report key is the part and the id": (
        r"The key is the record's part and the account's id, `\{part\}:\{user_id\}` in "
        r"`AuthService\._user_seal_failed`"
    ),
    "the single-check refusals are a floor": (
        r"At least these are refused on the first check, with no re-read: a record Vault transit "
        r"cannot verify"
    ),
    "the confirmation for the caller's own account has no form": (
        r"Where the id in its path is the caller's own, that page shows a note that the caller "
        r"cannot delete their own account, and no delete form"
    ),
}

#: The pre-hold wording of those two sentences (Lander hold 7091484059), each regex beside the
#: sentence it was written against: it must match that sentence, its positive control, and must
#: not match the statement, since the confirmation answers 200 rather than either.
_UNSCOPED = {
    r"answers 423 or lists the account as failed": (
        "A refusal inside that interval, from any of these routes or any other reader of the same "
        "account in that process, answers 423 or lists the account as failed and adds no row and "
        "no alert."
    ),
    r"answered the same way, a 423 or listed as failed": (
        "a record Vault transit cannot verify is answered the same way, a 423 or listed as "
        "failed, but reported under `integrity.authority_seal_unverifiable`"
    ),
}

#: Overclaims Lander hold 7095706239 asked to keep out of the statement, restored from this
#: branch's earlier bans and widened to the wording the hold found: each regex with the earlier
#: sentences it was written against, every one of which it must match, as its positive controls.
#: The throttle keys on the record's part and the account's id (``AuthService._user_seal_failed``),
#: not on the account; a record Vault transit cannot verify is refused at its first check, not
#: after the two failing reads a failing record takes; and that is not the only single-check case.
_REMOVED: dict[str, tuple[str, tuple[str, ...]]] = {
    "any reader of the same account": (
        r"other reader of the same account",
        ("from any of these routes or any other reader of the same account in that process",),
    ),
    "an unverifiable record answered as a failing one": (
        r"cannot verify[^.;]*answered as a (failing record|record that fails its seal)",
        (
            "a record Vault transit cannot verify is answered as a failing record is, but reported",
            "a record Vault transit cannot verify is refused at the first check that cannot verify "
            "it, with no further read, and then answered as a record that fails its seal is",
        ),
    ),
    "a counted exception": (
        r"(?<!at least )\bone exception\b",
        ("One exception: a `users` row with a timestamp or counter cell that does not parse",),
    ),
}


@pytest.mark.parametrize("name", sorted(_CONSOLE_SENTENCES))
def test_the_security_doc_states_the_console_sentences(name: str) -> None:
    text = _SECURITY_MD.read_text("utf-8")
    body = " ".join(text.split(_STATEMENT, 1)[1].split("\n\n", 1)[0].split())
    assert re.search(_CONSOLE_SENTENCES[name], body, re.IGNORECASE), name


def test_the_security_doc_no_longer_offers_the_delete_on_the_list_itself() -> None:
    """Main's "with its delete" described a delete form on the users list; this PR moved it behind
    the confirmation page (Lander hold 7090810151)."""
    text = _SECURITY_MD.read_text("utf-8")
    body = " ".join(text.split(_STATEMENT, 1)[1].split("\n\n", 1)[0].split())
    assert not re.search(r"by its id alone, with its delete\b", body, re.IGNORECASE)


@pytest.mark.parametrize("overclaim", sorted(_UNSCOPED))
def test_the_security_doc_does_not_state_the_423_without_the_confirmation(overclaim: str) -> None:
    assert re.search(overclaim, _UNSCOPED[overclaim], re.IGNORECASE), overclaim
    text = _SECURITY_MD.read_text("utf-8")
    body = " ".join(text.split(_STATEMENT, 1)[1].split("\n\n", 1)[0].split())
    assert not re.search(overclaim, body, re.IGNORECASE), overclaim


@pytest.mark.parametrize("name", sorted(_REMOVED))
def test_the_security_doc_drops_the_overclaim(name: str) -> None:
    shape, controls = _REMOVED[name]
    for control in controls:
        assert re.search(shape, control, re.IGNORECASE), (name, control)
    text = _SECURITY_MD.read_text("utf-8")
    body = " ".join(text.split(_STATEMENT, 1)[1].split("\n\n", 1)[0].split())
    assert not re.search(shape, body, re.IGNORECASE), name
