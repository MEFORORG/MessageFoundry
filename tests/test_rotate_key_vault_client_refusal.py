# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""`rotate-key` exits 2 when the Vault client for the store key cannot be built (vault BACKLOG #3247).

Under ``[store].key_provider = "vault"`` the command's first key check calls
``VaultKeyProvider.active_key()``, which builds the Vault client outside its own ``try``. At least
three checks in that build raise a bare :class:`ValueError`: the outbound length bound, the TLS
suite assertion and the strict-reader mount. None is a ``KeyProviderError``, so each one passed the
command's handler, reached the dispatch floor and exited 1. Exit 1 is an aborted rotation's code;
exit 2 is "could not start", which is what happened.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.store import keyprovider_vault
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.keyprovider import KeyProviderError
from messagefoundry.store.store import MessageStore

_AT_REST_ENV = (
    "MEFOR_STORE_ENCRYPTION_KEY",
    "MEFOR_STORE_ENCRYPTION_KEY_FILE",
    "MEFOR_STORE_ENCRYPTION_KEYS_RETIRED",
    "MEFOR_STORE_KEY_PROVIDER",
    "MEFOR_STORE_CIPHER_PROVIDER",
    "MEFOR_STORE_VAULT_ADDR",
    "MEFOR_STORE_VAULT_TOKEN",
    "MEFOR_STORE_VAULT_CA_FILE",
    "MEFOR_STORE_VAULT_TRANSIT_KEY",
    "MEFOR_STORE_VAULT_WRAPPED_DEK",
)

#: Stands in for the fixed text of a client-build refusal. Synthetic.
_REFUSAL = "Vault transit key provider: synthetic client-build refusal"


async def _seed(path: Path) -> None:
    cipher = make_cipher(generate_key(), ())
    store = await MessageStore.open(path, cipher=cipher, audit_mac_key=cipher.audit_mac_key())
    try:
        await store.record_audit("seed", actor="u", detail="{}")
    finally:
        await store.close()


def _select_the_vault_provider(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    for name in _AT_REST_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    db = tmp_path / "vault.db"
    asyncio.run(_seed(db))
    monkeypatch.setenv("MEFOR_STORE_KEY_PROVIDER", "vault")
    monkeypatch.setenv("MEFOR_STORE_VAULT_TRANSIT_KEY", "mefor-store-kek")
    monkeypatch.setenv("MEFOR_STORE_VAULT_WRAPPED_DEK", "vault:v1:c3ludGhldGlj")
    return db


def test_rotate_key_exits_2_when_the_vault_client_build_raises_a_bare_value_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    db = _select_the_vault_provider(monkeypatch, tmp_path)
    built: list[tuple[str | None, str | None]] = []

    def refuse(addr: str | None, token: str | None) -> object:
        built.append((addr, token))
        raise ValueError(_REFUSAL)

    monkeypatch.setattr(keyprovider_vault, "_build_client", refuse)

    assert main(["rotate-key", "--db", str(db)]) == 2
    captured = capsys.readouterr()
    assert len(built) == 1, "the client build under test never ran, or ran past the first check"
    assert "cannot load the active key for rotation" in captured.err, captured.err
    assert _REFUSAL in captured.err, captured.err
    assert "Traceback" not in captured.err, captured.err
    assert "OK:" not in captured.out, captured.out


def test_rotate_key_exits_2_on_a_real_client_build_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The premise, witnessed on the shipped build: a real check in it raises a bare ValueError.

    A token past the outbound header bound is refused before any socket opens. Without ``hvac`` the
    build stops earlier on a ``KeyProviderError``, which exited 2 on the old code too, so the test
    skips there rather than pass for the wrong reason."""
    pytest.importorskip("hvac")
    from messagefoundry.transports.rest import MAX_OUTBOUND_HEADER_VALUE_LEN

    db = _select_the_vault_provider(monkeypatch, tmp_path)
    token = "s" * (MAX_OUTBOUND_HEADER_VALUE_LEN + 1)  # synthetic, and over the bound by one
    monkeypatch.setenv("MEFOR_STORE_VAULT_ADDR", "https://vault.example.test:8200")
    monkeypatch.setenv("MEFOR_STORE_VAULT_TOKEN", token)

    assert main(["rotate-key", "--db", str(db)]) == 2
    captured = capsys.readouterr()
    assert "cannot load the active key for rotation" in captured.err, captured.err
    assert "X-Vault-Token" in captured.err, captured.err
    assert token not in captured.err + captured.out
    assert "Traceback" not in captured.err, captured.err


def test_rotate_key_still_exits_2_on_a_key_provider_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The control: the refusal the command already handled keeps its exit code and its text."""
    db = _select_the_vault_provider(monkeypatch, tmp_path)

    def refuse(addr: str | None, token: str | None) -> object:
        raise KeyProviderError(_REFUSAL)

    monkeypatch.setattr(keyprovider_vault, "_build_client", refuse)

    assert main(["rotate-key", "--db", str(db)]) == 2
    captured = capsys.readouterr()
    assert "cannot load the active key for rotation" in captured.err, captured.err
    assert _REFUSAL in captured.err, captured.err
