# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #5067, the added items from engine PR 3162's open findings.

* (A) ``admin-unlock``'s seal-refusal arm named the username as typed, where every other refusal
  after the read names the stored one. A case-insensitive server collation finds ``ADMIN`` as
  ``admin``; the double below stands in for that collation on SQLite.
* (C) ``admin-reset-totp``'s pre-write ``check()`` closed its store with a bare ``await
  store.close()``, so a failed close replaced the check's result with an exception.

Item (B), ``admin-set-notify-email``'s audit-refused text, is pinned in
``tests/test_admin_set_notify_email.py`` beside the busy-store test it changes. Synthetic data only.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest

import messagefoundry.__main__ as cli
from messagefoundry.__main__ import main
from messagefoundry.store.row_seal import USER_KIND, RowSealError
from messagefoundry.store.store import MessageStore


def test_admin_unlock_seal_refusal_names_the_stored_username(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from tests._phi_gate_provisions import setenv_at_rest_opt_out
    from tests.test_cli import _seed_locked

    monkeypatch.chdir(tmp_path)
    setenv_at_rest_opt_out(monkeypatch)
    db = tmp_path / "unlock.db"
    _seed_locked(db, locked_until=time.time() + 86_400)
    real_get = MessageStore.get_user_by_username

    async def folded(self: MessageStore, username: str) -> Any:
        return await real_get(self, username.lower())  # a case-insensitive collation

    async def refuse(*_a: object, **_k: object) -> object:
        raise RowSealError(USER_KIND)

    monkeypatch.setattr(MessageStore, "get_user_by_username", folded)
    monkeypatch.setattr(MessageStore, "clear_lockout", refuse)
    assert main(["admin-unlock", "--username", "ADMIN", "--db", str(db), "--json"]) == 1
    error = json.loads(capsys.readouterr().out)["error"]
    assert "integrity seal" in error
    assert "'admin'" in error and "'ADMIN'" not in error


def test_admin_reset_totp_check_survives_a_failed_close(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from tests.test_admin_reset_totp import _ADMIN, _CMD, _NEW_SECRET, _seed, _state

    monkeypatch.chdir(tmp_path)
    db = tmp_path / "reset.db"
    _seed(db)

    from messagefoundry.auth import totp

    def enrol(*, username: str, skew_steps: int, **_wording: str) -> tuple[str, str, float]:
        at = time.time()
        return totp.new_enrolment(_NEW_SECRET), totp.totp(_NEW_SECRET, now=at), at

    monkeypatch.setattr(cli, "_enrol_totp_at_terminal", enrol)
    monkeypatch.setattr(cli, "_show_on_terminal", lambda _text: None)
    real_close = MessageStore.close
    calls = {"n": 0}

    async def first_close_fails(self: MessageStore) -> None:
        calls["n"] += 1
        await real_close(self)
        if calls["n"] == 1:  # the pre-write check's close
            raise RuntimeError("synthetic close failure")

    monkeypatch.setattr(MessageStore, "close", first_close_fails)
    assert main([_CMD, "--username", _ADMIN, "--db", str(db)]) == 0
    out = capsys.readouterr()
    assert "OK: replaced" in out.out
    assert "closing the store failed (RuntimeError)" in out.err
    monkeypatch.undo()
    assert _state(db)["secret"] == _NEW_SECRET
