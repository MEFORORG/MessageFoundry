# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""`rotate-key` refuses a Transit key of a refused type with a clean exit 2 (BACKLOG #2109, limb 1).

In ``vault_transit`` mode with a local key set, ``resolve_active_key`` succeeds, so the command gets
past its first key check. The Transit key-TYPE check runs later, inside ``open_store`` ->
``build_store_cipher`` -> ``build_transit_cipher``. Its :class:`KeyProviderError` used to escape the
command's handlers and reach the last-resort hook, which exits 1 with a traceback.

The local key is load-bearing: without it the command stops at ``resolve_active_key`` and exits 2 on
the old code too, so this test would pass for the wrong reason.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.__main__ import main
from messagefoundry.store import crypto_transit
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.store import MessageStore

_AT_REST_ENV = (
    "MEFOR_STORE_ENCRYPTION_KEY",
    "MEFOR_STORE_ENCRYPTION_KEY_FILE",
    "MEFOR_STORE_ENCRYPTION_KEYS_RETIRED",
    "MEFOR_STORE_KEY_PROVIDER",
    "MEFOR_STORE_CIPHER_PROVIDER",
    "MEFOR_STORE_TRANSIT_KEY",
    "MEFOR_STORE_TRANSIT_AUDIT_KEY",
)


class _FakeTransit:
    """Only what the startup check reads: the key's type."""

    def __init__(self, key_type: str) -> None:
        self.key_type = key_type
        self.read_calls: list[str] = []

    def read_key(self, *, name: str) -> dict[str, Any]:
        self.read_calls.append(name)
        return {"data": {"name": name, "type": self.key_type}}


class _FakeClient:
    def __init__(self, transit: _FakeTransit) -> None:
        self.secrets = type("_Secrets", (), {"transit": transit})()


async def _seed(path: Path, key: str) -> None:
    cipher = make_cipher(key, ())
    store = await MessageStore.open(path, cipher=cipher, audit_mac_key=cipher.audit_mac_key())
    try:
        await store.record_audit("seed", actor="u", detail="{}")
    finally:
        await store.close()


def test_rotate_key_on_a_refused_transit_key_type_exits_2_without_a_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    for name in _AT_REST_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    db, key = tmp_path / "transit.db", generate_key()
    asyncio.run(_seed(db, key))

    transit = _FakeTransit("aes128-gcm96")  # withdrawn by owner ruling R4 (BACKLOG #2043)
    monkeypatch.setattr(crypto_transit, "_build_client", lambda addr, token: _FakeClient(transit))
    monkeypatch.setenv("MEFOR_STORE_CIPHER_PROVIDER", "vault_transit")
    monkeypatch.setenv("MEFOR_STORE_TRANSIT_KEY", "mefor-store")
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", key)  # gets the command past its first check

    assert main(["rotate-key", "--db", str(db)]) == 2
    captured = capsys.readouterr()
    assert transit.read_calls == ["mefor-store"], "the check under test never ran"
    assert "'aes128-gcm96'" in captured.err, captured.err
    assert "no command moves Transit ciphertext" in captured.err, captured.err
    assert "Traceback" not in captured.err, captured.err
    assert "OK:" not in captured.out, captured.out
