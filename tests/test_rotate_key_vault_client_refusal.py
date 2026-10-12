# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""`rotate-key` exits 2 when the Vault client for the store key cannot be built (vault BACKLOG #3247).

Under ``[store].key_provider = "vault"`` the command's first key check calls
``VaultKeyProvider.active_key()``, which builds the Vault client outside its own ``try``. At least
three checks in that build raise a bare :class:`ValueError`: the outbound length bound, the TLS
suite assertion and the strict-reader mount. None is a ``KeyProviderError``, so each one passed the
command's handler, reached the dispatch floor and exited 1. Exit 1 is an aborted rotation's code;
exit 2 is "could not start", which is what happened.

No store is built. The command resolves the key before it looks for a store, so each test stops at
the key check, and each asserts that check's own line. The later "no store" refusal also exits 2,
so the exit code alone would not show which check answered.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.store import keyprovider_vault
from messagefoundry.store.keyprovider import KeyProviderError

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
_KEY_CHECK_LINE = "cannot load the active key for rotation"


def _select_the_vault_provider(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> str:
    """Select the Vault key provider and return a store path. Nothing is created there."""
    for name in _AT_REST_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_KEY_PROVIDER", "vault")
    monkeypatch.setenv("MEFOR_STORE_VAULT_TRANSIT_KEY", "mefor-store-kek")
    monkeypatch.setenv("MEFOR_STORE_VAULT_WRAPPED_DEK", "vault:v1:c3ludGhldGlj")
    return str(tmp_path / "vault.db")


@pytest.mark.parametrize(
    "refusal", [ValueError, KeyProviderError], ids=["bare-value-error", "key-provider-error"]
)
def test_rotate_key_exits_2_when_the_vault_client_build_refuses(
    refusal: type[Exception],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A bare ``ValueError`` exited 1 before the fix. ``KeyProviderError`` is the control: the
    command already handled it, and it keeps its exit code and its text."""
    db = _select_the_vault_provider(monkeypatch, tmp_path)
    builds = 0

    def refuse(addr: str | None, token: str | None) -> object:
        nonlocal builds
        builds += 1
        raise refusal(_REFUSAL)

    monkeypatch.setattr(keyprovider_vault, "_build_client", refuse)

    assert main(["rotate-key", "--db", db]) == 2
    captured = capsys.readouterr()
    assert builds == 1, "the client build under test never ran, or ran past the first check"
    assert _KEY_CHECK_LINE in captured.err, captured.err
    assert _REFUSAL in captured.err, captured.err
    assert "Traceback" not in captured.err, captured.err
    assert "OK:" not in captured.out, captured.out


def test_a_value_error_subclass_still_reaches_the_dispatch_floor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The arm takes exactly ``ValueError``. A subclass can quote what a parser or a server read,
    so it is left to the dispatch floor, which exits 1 as it did before."""

    class _Parse(ValueError):
        pass

    db = _select_the_vault_provider(monkeypatch, tmp_path)

    def refuse(addr: str | None, token: str | None) -> object:
        raise _Parse(_REFUSAL)

    monkeypatch.setattr(keyprovider_vault, "_build_client", refuse)

    assert main(["rotate-key", "--db", db]) == 1
    assert _KEY_CHECK_LINE not in capsys.readouterr().err


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

    assert main(["rotate-key", "--db", db]) == 2
    captured = capsys.readouterr()
    assert _KEY_CHECK_LINE in captured.err, captured.err
    assert "X-Vault-Token" in captured.err, captured.err
    assert token not in captured.err + captured.out
    assert "Traceback" not in captured.err, captured.err
