# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""`rotate-key` refuses ``vault_transit`` mode up front with a clean exit 2 (BACKLOG #2109).

Under ``[store].cipher_provider = "vault_transit"`` the store's values are sealed inside Transit, and
the store's re-encrypt pass refuses a Transit cipher (BACKLOG #1165), so no run of the command can
rotate anything there. It used to find that out late: it resolved a local key (or told the operator
to set one, which this mode never reads), dialled Vault, opened the store writable, and only then
exited 2. It now refuses before any of that, and says what to do instead.

Limb 1 of the row, a refused Transit key TYPE reaching the last-resort hook with exit 1 (engine PR
2153), cannot recur on this command now: it never builds the Transit cipher. The type check itself
is covered where the cipher is built.
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
from tests._vault_hop_env import STORE, supply_vault_hop

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


@pytest.mark.parametrize(
    ("key_type", "local_key"),
    [
        # A key type the cipher accepts, with a local key: the command used to dial Vault, open the
        # store and only then refuse, from the re-encrypt pass.
        ("aes256-gcm96", True),
        # No local key: the command used to tell the operator to set MEFOR_STORE_ENCRYPTION_KEY,
        # which this mode never reads, so following it led only to the late refusal above.
        ("aes256-gcm96", False),
        # A refused type (owner ruling R4, BACKLOG #2043): limb 1's case, exit 2 from the open
        # since engine PR 2153. It now refuses before the open, so the type is never read.
        ("aes128-gcm96", True),
    ],
)
def test_rotate_key_refuses_vault_transit_mode_before_vault_or_the_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    key_type: str,
    local_key: bool,
) -> None:
    for name in _AT_REST_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    db, key = tmp_path / "transit.db", generate_key()
    asyncio.run(_seed(db, key))
    before = db.read_bytes()

    transit = _FakeTransit(key_type)
    built: list[str] = []

    def _client(addr: str, token: str, **_: object) -> _FakeClient:
        built.append(addr)
        return _FakeClient(transit)

    monkeypatch.setattr(crypto_transit, "_build_client", _client)
    monkeypatch.setenv("MEFOR_STORE_CIPHER_PROVIDER", "vault_transit")
    supply_vault_hop(monkeypatch, STORE)  # required since BACKLOG #2851
    monkeypatch.setenv("MEFOR_STORE_TRANSIT_KEY", "mefor-store")
    if local_key:
        monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", key)

    assert main(["rotate-key", "--db", str(db)]) == 2
    captured = capsys.readouterr()
    assert "does not run under [store].cipher_provider" in captured.err, captured.err
    assert "No command moves Transit ciphertext" in captured.err, captured.err
    assert "Nothing was changed." in captured.err, captured.err
    assert "MEFOR_STORE_ENCRYPTION_KEY to the new active key" not in captured.err, captured.err
    assert "Traceback" not in captured.err, captured.err
    assert "OK:" not in captured.out, captured.out
    assert built == [], "the command dialled Vault before refusing"
    assert transit.read_calls == [], "the command read the Transit key before refusing"
    assert db.read_bytes() == before, "the command wrote to the store before refusing"
