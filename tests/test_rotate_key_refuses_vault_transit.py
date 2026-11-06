# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""`rotate-key` refuses ``vault_transit`` mode up front with a clean exit 2 (BACKLOG #2109).

Under ``[store].cipher_provider = "vault_transit"`` the store's re-encrypt pass refuses the Transit
cipher (BACKLOG #1165), so no run of the command can rotate anything there. It used to find that
out late. With a local key it resolved the key, dialled Vault, opened the store writable, and only
then exited 2. Without one it told the operator to set a key the Transit cipher never reads. It now
refuses before any of that, and says what to do instead.

Limb 1 of the row, a refused Transit key TYPE reaching the last-resort hook with exit 1 (engine PR
2153), cannot recur on this command now: it never builds the Transit cipher. The key-type check is
covered where the cipher is built, in ``tests/test_crypto_transit.py``.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

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


async def _seed(path: Path, key: str) -> None:
    cipher = make_cipher(key, ())
    store = await MessageStore.open(path, cipher=cipher, audit_mac_key=cipher.audit_mac_key())
    try:
        await store.record_audit("seed", actor="u", detail="{}")
    finally:
        await store.close()


@pytest.mark.parametrize(
    "local_key",
    [
        # The old code resolved this key, dialled Vault, opened the store and only then refused, from
        # the re-encrypt pass.
        True,
        # The old code told the operator to set MEFOR_STORE_ENCRYPTION_KEY, which the Transit
        # cipher never reads, so following it led only to the late refusal above.
        False,
    ],
)
def test_rotate_key_refuses_vault_transit_mode_before_vault_or_the_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    local_key: bool,
) -> None:
    for name in _AT_REST_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    db, key = tmp_path / "transit.db", generate_key()
    asyncio.run(_seed(db, key))
    # The sidecars too: a writable WAL open puts its writes in transit.db-wal before a checkpoint.
    before = {p.name: p.read_bytes() for p in tmp_path.glob("transit.db*")}

    built: list[str] = []

    def _client(addr: str, token: str, **_: object) -> object:
        built.append(addr)
        raise AssertionError("rotate-key dialled Vault before refusing")

    monkeypatch.setattr(crypto_transit, "_build_client", _client)
    monkeypatch.setenv("MEFOR_STORE_CIPHER_PROVIDER", "vault_transit")
    supply_vault_hop(monkeypatch, STORE)  # required since BACKLOG #2851
    monkeypatch.setenv("MEFOR_STORE_TRANSIT_KEY", "mefor-store")
    if local_key:
        monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", key)

    assert main(["rotate-key", "--db", str(db)]) == 2
    captured = capsys.readouterr()
    assert "does not run under [store].cipher_provider" in captured.err, captured.err
    assert "between two Transit keys" in captured.err, captured.err
    assert "Retiring an old version of the audit key" in captured.err, captured.err
    # The refusal names the Vault settings that retire a version itself, rather than pointing at a
    # document to name them, and the section it does point at still exists.
    assert "data key's min_decryption_version" in captured.err, captured.err
    assert "audit key's min_encryption_version" in captured.err, captured.err
    assert "Trimming a version" in captured.err, captured.err
    assert "says which Vault settings retire one" not in captured.err, captured.err
    security = (Path(__file__).resolve().parents[1] / "docs" / "SECURITY.md").read_text("utf-8")
    assert "**Retiring an old version of the audit key breaks the chain.**" in security
    assert "Nothing was changed." in captured.err, captured.err
    assert "needs an active key" not in captured.err, captured.err
    assert "Traceback" not in captured.err, captured.err
    assert "OK:" not in captured.out, captured.out
    assert built == [], "the command dialled Vault before refusing"
    after = {p.name: p.read_bytes() for p in tmp_path.glob("transit.db*")}
    assert after == before, "the command wrote to the store before refusing"
