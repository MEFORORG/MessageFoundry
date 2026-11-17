# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #4936, the owner ruling of 2026-11-04.

``rotate-key`` opens its rotation record through ``open_store``'s ``before_first_write`` hook, so a
run killed inside the store open after the hook leaves any record it opened."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.__main__ import main
from messagefoundry.config.ai_policy import SecurityEnforcement
from messagefoundry.config.settings import SecretRotationSettings, StoreSettings
from messagefoundry.pipeline.secret_rotation import (
    ROTATION_RECORD_ID,
    dek_fingerprint,
    reconcile_rotation_meta,
)
from messagefoundry.store.base import open_store
from messagefoundry.store.crypto import generate_key
from messagefoundry.store.store import (
    MessageStore,
    audit_chain_rolled,
)
from tests.test_rotate_key_rotation_record import (
    _DEK,
    _OLD_DATE,
    _env,
    _key_id,
    _open,
    _seed,
    _seed_keyless_chain,
)


class _Killed(Exception):
    """Stands in for a kill inside the store open, after the hook ran."""


def _kill_after_the_hook(monkeypatch: pytest.MonkeyPatch) -> None:
    async def killed(*_args: object, **_kwargs: object) -> None:
        raise _Killed("killed inside the store open")

    # The salt bind is the open's first write under the key, right after the hook.
    monkeypatch.setattr("messagefoundry.store.store.bind_store_salt", killed)


async def _reconcile(db: Path, key: str, *retired: str) -> dict[str, Any]:
    store = await _open(db, key, *retired)
    try:
        await reconcile_rotation_meta(
            store,
            SecretRotationSettings(),
            dek_key_id=_key_id(key),
            enforcement=SecurityEnforcement.WARN,
            env_values={},
            audit_rolled=audit_chain_rolled(store),
        )
        return dict(await store.get_secret_rotation_meta())
    finally:
        await store.close()


def test_a_run_killed_inside_the_open_on_a_store_with_no_keyed_chain_leaves_no_stamp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """#4936 step 3. On the code before the hook no record existed at the kill, and this start
    stamped the new key, because a store with no keyed chain has nothing else to hold it."""
    monkeypatch.chdir(tmp_path)
    db, uploads, key_a, key_b = (
        tmp_path / "k.db",
        tmp_path / "uploads",
        generate_key(),
        generate_key(),
    )
    asyncio.run(_seed_keyless_chain(db, uploads, key_a))
    _env(monkeypatch, key_b, key_a, uploads)
    with monkeypatch.context() as patch:
        _kill_after_the_hook(patch)
        # run_guarded turns the uncaught kill into a failing exit.
        assert main(["rotate-key", "--db", str(db)]) != 0
    capsys.readouterr()
    rows = asyncio.run(_reconcile(db, key_b, key_a))
    assert rows[ROTATION_RECORD_ID].fingerprint == dek_fingerprint(_key_id(key_b))
    assert rows[_DEK].fingerprint == dek_fingerprint(_key_id(key_a))
    assert rows[_DEK].last_rotated == _OLD_DATE


def test_the_hook_runs_before_the_first_write_and_not_on_a_read_only_open(tmp_path: Path) -> None:
    """The hook sees the store before the salt bind and the at-rest sweep, and a read-only open
    never runs it."""
    db, key = tmp_path / "h.db", generate_key()
    asyncio.run(_seed(db, tmp_path / "uploads", key))
    seen: list[str] = []

    async def hook(store: object) -> None:
        assert isinstance(store, MessageStore)
        assert store._cipher_foreign  # the salt is not bound yet
        seen.append("hook")

    async def opened(read_only: bool) -> None:
        settings = StoreSettings(path=str(db), encryption_key=key)
        store = await open_store(
            settings, read_only=read_only, keyless_chain_refusal=None, before_first_write=hook
        )
        await store.close()

    asyncio.run(opened(False))
    assert seen == ["hook"]
    asyncio.run(opened(True))
    assert seen == ["hook"]
