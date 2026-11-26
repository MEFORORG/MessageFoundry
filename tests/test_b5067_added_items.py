# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #5067, the added items from engine PR 3162's open findings.

* (C) ``admin-reset-totp``'s pre-write ``check()`` closed its store with a bare ``await
  store.close()``, so a failed close replaced the check's result with an exception.

Item (B), ``admin-set-notify-email``'s audit-refused text, is pinned in
``tests/test_admin_set_notify_email.py`` beside the busy-store test it changes. Item (A) is not
built: ``tests/test_cli.py::test_admin_unlock_names_the_stored_username`` pins the typed name on
the seal refusal deliberately, so no value from a record that failed its seal is printed.
Synthetic data only.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

import messagefoundry.__main__ as cli
from messagefoundry.__main__ import main
from messagefoundry.store.store import MessageStore


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
