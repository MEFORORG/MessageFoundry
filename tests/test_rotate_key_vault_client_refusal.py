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

#: Stands in for the fixed text of a client-build refusal. Synthetic, and longer than the 200
#: characters ``safe_exc`` keeps: the TLS suite refusals are about 400 to 500, and their last
#: sentence says what to change, so a cut would drop the remedy.
_REFUSAL = "Vault transit key provider: synthetic client-build refusal. " + "Change it. " * 20
_KEY_CHECK_LINE = "cannot load the active key for rotation"


class _ParseError(ValueError):
    """A ``ValueError`` subclass, as a parser raises."""


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
    "refusal",
    [ValueError, _ParseError, KeyProviderError],
    ids=["bare-value-error", "value-error-subclass", "key-provider-error"],
)
def test_rotate_key_exits_2_when_the_vault_client_build_refuses(
    refusal: type[Exception],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A ``ValueError`` exited 1 before the fix, bare or subclassed. A subclass is taken too,
    because the store open already takes it: ``build_store_cipher`` raises any ``ValueError`` from
    the same build as ``StoreCipherConfigError``, and the command exits 2 on that. The refusal is
    printed whole. ``KeyProviderError`` is the control: the command already handled it."""
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


def test_a_unicode_error_at_the_key_check_does_not_print_the_byte_it_failed_on(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A ``UnicodeDecodeError`` is a ``ValueError``, and its own text quotes the byte it failed on.
    At this check that byte can be one of the store key's: a DPAPI key file that unprotects to
    bytes that are not ASCII raises one. So the arm exits 2 and prints the error without the byte.
    Raised here from the Vault client build, which reaches the same arm. Synthetic bytes."""
    db = _select_the_vault_provider(monkeypatch, tmp_path)

    def refuse(addr: str | None, token: str | None) -> object:
        return bytes([0x41, 0x42, 0x9C]).decode("ascii")

    monkeypatch.setattr(keyprovider_vault, "_build_client", refuse)

    assert main(["rotate-key", "--db", db]) == 2
    captured = capsys.readouterr()
    assert _KEY_CHECK_LINE in captured.err, captured.err
    assert "UnicodeDecodeError" in captured.err, captured.err
    assert "0x9c" not in captured.err.lower(), captured.err


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
