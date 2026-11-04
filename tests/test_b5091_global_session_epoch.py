# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The every-account revoke ends a session whatever account list it read (BACKLOG #5091).

Before the global session epoch, ``revoke_all_sessions`` raised the epoch only of the accounts its
one read of the account list returned. On the server stores a session of an account that read did
not return, and that the sweep did not reach either, stayed live. So did a missed session of an
account whose record failed its seal at the revoke, once the record verified again, because the
revoke cannot raise a failing account's epoch.

The contract replays both states on a keyed store with raw SQL, because neither the gap nor the
seal failure can be scheduled from outside a running revoke: the account row is put back as the
read that missed it would have left it, and the session row as the sweep that missed it would have
left it. Each keeps a valid seal, so the only thing still ending the session is the global epoch.
Every refusal has a control beside it. It runs on SQLite here, and on the server legs from
``tests/test_postgres_store.py`` and ``tests/test_sqlserver_store.py``. The Postgres leg also runs
a sign-in that commits while a revoke is between its sweep and its commit, the interleaving the gap
was, and both server legs run a revoke racing sign-ins, which a lock-order cycle would deadlock.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from dataclasses import fields
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.auth.service import AuthService
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.store import MessageStore, UserRow, session_seal_ok
from tests.test_b2614_revoke_all import RawSql, _mint, _sqlite_raw, _user


async def _put_back_account(raw: RawSql, row: UserRow) -> None:
    """Write ``row`` back whole, as the store sealed it: the account a revoke's read did not
    return keeps the epoch it had, and its seal still verifies."""
    names = [f.name for f in fields(UserRow) if f.name != "id"]
    await raw(
        "UPDATE users SET " + ", ".join(f"{n}=?" for n in names) + " WHERE id=?",
        (*row.write_params(), row.id),
    )


async def _put_back_session(raw: RawSql, token: str, seal: str) -> None:
    """Unrevoke the row and give it back the seal it had: what a sweep that missed it leaves."""
    await raw(
        "UPDATE sessions SET revoked_at=NULL, seal=? WHERE token_hash=?", (seal, hash_token(token))
    )


async def assert_global_epoch_contract(store: Any, raw: RawSql) -> None:
    """Drive the global session epoch through its contract on ``store``'s backend. The account ids
    are fresh each run, so a shared server database's other rows do not change the outcome."""
    sealer = store.row_sealer()
    assert sealer is not None, "the contract needs a store opened with a store key"
    service = AuthService(store, AuthSettings())
    run = uuid.uuid4().hex[:8]
    carol, dave, erin = f"b5091-c-{run}", f"b5091-d-{run}", f"b5091-e-{run}"
    for user_id in (carol, dave, erin):
        await _user(store, user_id)

    # --- a session is stamped with the global epoch it was minted under ------------------------
    kept = await _mint(store, dave)
    missed = await _mint(store, carol)
    failing = await _mint(store, erin)
    carol_before = await store.get_user(carol)
    erin_before = await store.get_user(erin)
    missed_before = await store.get_session(hash_token(missed))
    failing_before = await store.get_session(hash_token(failing))
    assert carol_before is not None and carol_before.row is not None
    assert erin_before is not None and erin_before.row is not None
    assert missed_before is not None and failing_before is not None
    epoch = carol_before.global_session_epoch
    assert missed_before.global_epoch == epoch
    for token in (kept, missed, failing):  # control: each resolves before the revoke
        assert await service.identity_for_token(token) is not None

    # --- an account whose record fails its seal at the revoke keeps its own epoch --------------
    await raw("UPDATE users SET authz_seal=? WHERE id=?", ("mfseal:v1:b5091:bogus", erin))
    assert await store.revoke_all_sessions(except_token_hash=hash_token(kept)) >= 2
    erin_raw = await store.get_user(erin)
    assert erin_raw is not None and erin_raw.session_epoch == erin_before.session_epoch

    # --- the revoke raised the global epoch, and the kept session carries the new one ----------
    carol_after = await store.get_user(carol)
    assert carol_after is not None and carol_after.global_session_epoch == epoch + 1
    # The account loop still raises each account it read: the backstop if the unsealed global
    # row is ever lowered, which nothing else here would notice going missing.
    assert carol_after.session_epoch == carol_before.session_epoch + 1
    survivor = await store.get_session(hash_token(kept))
    assert survivor is not None and survivor.global_epoch == epoch + 1
    assert session_seal_ok(sealer, survivor)
    assert await service.identity_for_token(kept) is not None

    # --- a missed session of an account the read did not return still ends --------------------
    await _put_back_account(raw, carol_before.row)
    await _put_back_session(raw, missed, missed_before.seal)
    replayed = await store.get_session(hash_token(missed))
    restored = await store.get_user(carol)
    assert replayed is not None and replayed.revoked_at is None
    assert session_seal_ok(sealer, replayed)  # the old seal holds...
    assert restored is not None and replayed.user_epoch == restored.session_epoch  # ...so does
    assert replayed.global_epoch != restored.global_session_epoch  # ...all but the global epoch
    assert await service.identity_for_token(missed) is None  # the gate, before anything ends it
    fresh = await _mint(store, carol)
    assert await service.identity_for_token(fresh) is not None  # control: the account verifies

    # --- and so does one of an account whose record verifies again after the revoke ------------
    await _put_back_account(raw, erin_before.row)
    await _put_back_session(raw, failing, failing_before.seal)
    assert await service.list_sessions(erin) == []  # the session list, before the gate ends it
    later = await _mint(store, erin)
    assert await service.identity_for_token(later) is not None  # control: the record verifies
    assert [r.token_hash for r in await service.list_sessions(erin)] == [hash_token(later)]
    assert await service.identity_for_token(failing) is None

    # --- a kept session behind on the global epoch alone is not stamped back (BACKLOG #4975) ----
    # Its account is put back beside it, so its account epoch is current and only the global
    # epoch has moved past it: a re-stamp that checked the account epoch alone would revive it.
    frank = f"b5091-f-{run}"
    await _user(store, frank)
    behind = await _mint(store, frank)
    frank_before = await store.get_user(frank)
    behind_before = await store.get_session(hash_token(behind))
    assert frank_before is not None and frank_before.row is not None
    assert behind_before is not None
    assert await store.revoke_all_sessions() >= 1
    await _put_back_account(raw, frank_before.row)
    await _put_back_session(raw, behind, behind_before.seal)
    replayed = await store.get_session(hash_token(behind))
    restored = await store.get_user(frank)
    assert replayed is not None and restored is not None
    assert replayed.user_epoch == restored.session_epoch  # current on its account's epoch...
    assert replayed.global_epoch == restored.global_session_epoch - 1  # ...one global epoch behind
    await store.revoke_all_sessions(except_token_hash=hash_token(behind))
    left = await store.get_session(hash_token(behind))
    assert left is not None and left.revoked_at is None
    assert (left.user_epoch, left.global_epoch) == (
        behind_before.user_epoch,
        behind_before.global_epoch,
    )  # not re-stamped with either new epoch
    assert await service.identity_for_token(behind) is None
    # Control: a current session kept by the same revoke is stamped with both new epochs.
    current = await _mint(store, frank)
    await store.revoke_all_sessions(except_token_hash=hash_token(current))
    stamped = await store.get_session(hash_token(current))
    frank_after = await store.get_user(frank)
    assert stamped is not None and frank_after is not None
    assert stamped.user_epoch == frank_after.session_epoch
    assert stamped.global_epoch == frank_after.global_session_epoch
    assert await service.identity_for_token(current) is not None


async def assert_revoke_all_races_sign_ins(
    store: Any, *, rounds: int = 3, accounts: int = 6
) -> None:
    """A revoke of every account racing sign-ins finishes, and no sign-in in the race is minted
    dead: an unrevoked session stamped with its account's current epoch carries the current
    global epoch too, and resolves. A sign-in that waited behind the revoke and read the two
    epochs from different moments would break that. A lock-order cycle would surface here as the
    server's deadlock error, raised out of the gather."""
    service = AuthService(store, AuthSettings())
    run = uuid.uuid4().hex[:8]
    ids = [f"b5091-r{n}-{run}" for n in range(accounts)]
    for user_id in ids:
        await _user(store, user_id)
    for _ in range(rounds):
        results = await asyncio.gather(
            store.revoke_all_sessions(), *(_mint(store, user_id) for user_id in ids)
        )
        for user_id, token in zip(ids, (str(t) for t in results[1:]), strict=True):
            row = await store.get_session(hash_token(token))
            account = await store.get_user(user_id)
            assert row is not None and account is not None
            if row.revoked_at is None and row.user_epoch == account.session_epoch:
                assert row.global_epoch == account.global_session_epoch
                assert await service.identity_for_token(token) is not None


@pytest.fixture
async def keyed(tmp_path: Path) -> AsyncIterator[tuple[MessageStore, Path]]:
    path = tmp_path / "b5091.db"
    store = await MessageStore.open(path, cipher=make_cipher(generate_key(), write_v2=True))
    try:
        yield store, path
    finally:
        await store.close()


async def test_the_global_epoch_contract_holds_on_sqlite(
    keyed: tuple[MessageStore, Path],
) -> None:
    store, path = keyed
    await assert_global_epoch_contract(store, _sqlite_raw(path))


async def test_a_revoke_racing_sign_ins_finishes_on_sqlite(
    keyed: tuple[MessageStore, Path],
) -> None:
    store, _path = keyed
    await assert_revoke_all_races_sign_ins(store)


async def test_the_revoke_refuses_a_store_with_no_global_epoch_row(
    keyed: tuple[MessageStore, Path],
) -> None:
    """RED when the raise of the global epoch can match no row and the revoke still reports
    success: every session minted before it would then outlive it on the gap's terms."""
    store, path = keyed
    await _user(store, "b5091-gone")
    token = await _mint(store, "b5091-gone")
    await _sqlite_raw(path)("DELETE FROM global_session_epoch", ())
    with pytest.raises(RuntimeError, match="global_session_epoch row is missing"):
        await store.revoke_all_sessions()
    row = await store.get_session(hash_token(token))
    assert row is not None and row.revoked_at is None  # rolled back: nothing was revoked
    with pytest.raises(RuntimeError, match="global_session_epoch row is missing"):
        await store.get_user("b5091-gone")  # a user read refuses by the same name
    with pytest.raises(RuntimeError, match="global_session_epoch row is missing"):
        await _mint(store, "b5091-gone")  # and so does a sign-in, never a bare TypeError


async def test_a_reopen_keeps_a_raised_global_epoch_and_seeds_a_missing_row(
    tmp_path: Path,
) -> None:
    """The schema's seed keeps a raised value, and an open after the row was deleted seeds it
    again, so the revoke works there."""
    path = tmp_path / "seed.db"
    store = await MessageStore.open(path)
    try:
        await store.revoke_all_sessions()
        await store.revoke_all_sessions()
    finally:
        await store.close()
    store = await MessageStore.open(path)
    try:
        await _user(store, "b5091-seed")
        user = await store.get_user("b5091-seed")
        assert user is not None and user.global_session_epoch == 2
    finally:
        await store.close()
    await _sqlite_raw(path)("DELETE FROM global_session_epoch", ())
    store = await MessageStore.open(path)
    try:
        user = await store.get_user("b5091-seed")
        assert user is not None and user.global_session_epoch == 0  # seeded again
        await store.revoke_all_sessions()
        user = await store.get_user("b5091-seed")
        assert user is not None and user.global_session_epoch == 1
    finally:
        await store.close()


def test_the_security_doc_states_the_closed_gap() -> None:
    """RED when ``docs/SECURITY.md`` goes back to the gap's wording, or stops naming this row and
    the seal-failure case where it states the limits of the session sweep."""
    text = (Path(__file__).resolve().parents[1] / "docs" / "SECURITY.md").read_text(
        encoding="utf-8"
    )
    flat = " ".join(text.split())
    sweep = flat.split("**Limits of the session sweep.**", 1)[1]
    sweep = sweep.split("**A bind and a user delete take one lock order", 1)[0]
    assert "BACKLOG #5091" in sweep
    assert "global session epoch" in sweep
    assert "fails its seal" in sweep
    assert "raises the session epoch only for the accounts its one read" not in flat
    assert "closing it is follow-up work" not in flat
