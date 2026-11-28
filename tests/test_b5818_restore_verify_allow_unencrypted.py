# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5818: ``restore-verify`` did not pass ``[backup].allow_unencrypted`` to
``run_restore_verify``, so in the shipped code a keyed site that set it would see its plaintext
archive refused as ``KEY_MISMATCH``, with a remedy naming the setting it had already set.

The archive is a synthetic one written with no key; the verify then runs under a store key, which
is the downgrade shape the guard exists for. With the setting off the refusal still stands, and it
is the downgrade guard's refusal, not a key-fingerprint miss.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.store.crypto import generate_key
from tests.test_restore_verify import _backup


async def _plaintext_archive(tmp_path: Path) -> str:
    store, archive, _ = await _backup(tmp_path, None, allow_unencrypted=True)
    await store.close()
    return archive


@pytest.mark.parametrize(
    ("allow", "status", "rc"), [(True, "PASS", 0), (False, "KEY_MISMATCH", 1)], ids=["set", "unset"]
)
def test_restore_verify_honours_backup_allow_unencrypted_on_a_keyed_site(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    allow: bool,
    status: str,
    rc: int,
) -> None:
    archive = asyncio.run(_plaintext_archive(tmp_path))
    svc = tmp_path / "messagefoundry.toml"
    svc.write_text(f"[backup]\nallow_unencrypted = {str(allow).lower()}\n", encoding="utf-8")
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    argv = [
        "restore-verify",
        archive,
        "--service-config",
        str(svc),
        "--db",
        str(tmp_path / "keyed.db"),
        "--json",
    ]
    code = main(argv)
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["status"] == status, out
    assert code == rc, out
    if not allow:
        # The control fails for the right reason: the downgrade guard named the plaintext archive.
        assert "plaintext archive" in str(payload.get("reason")), out
