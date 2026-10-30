# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #3471 -- refusal text on the store key and the Vault hop, from the reviews of engine
PR 2293.

Item 4: a DPAPI key file that unprotects to bytes that are not ASCII made ``load_protected_key``
raise a ``UnicodeDecodeError``, and ``build_store_cipher`` printed its text, which names a byte of
the key. ``audit-verify``, ``audit-anchor``, ``admin-unlock`` and ``admin-set-notify-email`` would
have printed it. The key file now refuses with fixed text, and ``build_store_cipher`` renders any
codec error without its bytes and without a chain that holds them.

Item 3: ``VaultKeyProvider.active_key`` lets a ``ValueError``, ``OSError`` or ``re.error`` from the
client build leave as ``KeyProviderError``, and ``backup``, ``restore-verify`` and ``restore`` have
a key arm, so none of them reaches the dispatch floor.

Item 2: a hop refusal keeps its text only when it is exactly the Vault hop's marked
``VaultHopRefused``: in ``provision-admin``'s secret-provider arm, in both Vault client builds and
in the Vault probe's ``_why``.

All key bytes, hosts and tokens here are synthetic. Severity is conditional (CLAUDE.md section 0).
"""

from __future__ import annotations

import re
import traceback
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import messagefoundry.secrets_dpapi as secrets_dpapi
from messagefoundry.__main__ import main
from messagefoundry.config.settings import StoreSettings
from messagefoundry.config.tls_policy import InsecureHopRefused, is_vault_hop_refusal
from messagefoundry.secrets_dpapi import DpapiError, load_protected_key
from messagefoundry.store import base as store_base
from messagefoundry.store.base import StoreCipherConfigError, build_store_cipher
from messagefoundry.store.crypto import generate_key
from messagefoundry.store.keyprovider import KeyProviderError
from tests._extras_probe import OPTIONAL_EXTRAS, extra_is_installed
from tests.test_keyless_chain_every_command import (
    _KEY_REFUSING_COMMANDS,
    _argv,
    _keyed_chain,
)
from tests.test_keyless_chain_every_command import shell as shell  # noqa: F401  (the fixture)

#: What a DPAPI key file unprotects to here: base64-looking text with one byte that is not ASCII.
_KEY_BYTES = b"c3ludGhldGljLWtleQ\xd7=="
#: Every spelling of that byte a decode error's text, its repr or a print could carry.
_BYTE_SPELLINGS = ("0xd7", "\\xd7", "\xd7")

_HOST = "vault-host.synthetic.test"
_vault = pytest.mark.skipif(
    not extra_is_installed(OPTIONAL_EXTRAS["vault"]),
    reason="the [vault] extra (hvac + requests + urllib3) is not installed in this interpreter",
)


def _assert_no_key_byte(text: str) -> None:
    for spelling in _BYTE_SPELLINGS:
        assert spelling not in text, text


def _whole(exc: BaseException) -> str:
    """The text and the traceback a handler or a last-resort hook could print, chain included."""
    return str(exc) + "".join(traceback.format_exception(exc))


@pytest.fixture
def key_file(shell: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A key file whose unprotect returns :data:`_KEY_BYTES`, on any platform, in a shell with no
    other at-rest variable set."""
    path = shell / "store.key"
    path.write_bytes(b"synthetic protected blob")
    monkeypatch.setattr(secrets_dpapi, "dpapi_unprotect", lambda blob: _KEY_BYTES)
    return path


# --- item 4: no key byte in the refusal --------------------------------------------------------


def test_a_key_file_that_is_not_ascii_refuses_with_fixed_text(key_file: Path) -> None:
    with pytest.raises(DpapiError) as caught:
        load_protected_key(key_file)
    assert "not ASCII" in str(caught.value) and str(key_file) in str(caught.value)
    _assert_no_key_byte(_whole(caught.value))
    assert caught.value.__cause__ is None and caught.value.__context__ is None


def test_the_cipher_build_names_no_byte_of_the_key_file(key_file: Path) -> None:
    """Through the key provider seam, as every store open builds it."""
    with pytest.raises(DpapiError) as caught:
        build_store_cipher(StoreSettings(encryption_key_file=str(key_file)))
    _assert_no_key_byte(_whole(caught.value))


class _CodecErrorProvider:
    """A key provider whose key source hands back bytes that do not decode."""

    def __init__(self, error: Exception) -> None:
        self._error = error

    def active_key(self) -> str | None:
        raise self._error

    def retired_keys(self) -> list[str]:
        return []


def _decode_error() -> UnicodeDecodeError:
    try:
        _KEY_BYTES.decode("ascii")
    except UnicodeDecodeError as exc:
        return exc
    raise AssertionError("the synthetic key bytes decoded as ASCII")


@pytest.mark.parametrize(
    "error",
    [_decode_error(), ValueError("wrapped", _decode_error())],
    ids=["codec-error", "holds-a-codec-error"],
)
def test_build_store_cipher_renders_a_codec_error_without_its_bytes(
    error: Exception, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Any key source, not only DPAPI: the build renders the codec error and does not chain it."""
    monkeypatch.setattr(
        store_base,
        "resolve_key_provider",
        lambda settings, posture=None: _CodecErrorProvider(error),
    )
    with pytest.raises(StoreCipherConfigError) as caught:
        build_store_cipher(StoreSettings())
    _assert_no_key_byte(_whole(caught.value))
    assert caught.value.__cause__ is None and caught.value.__context__ is None


def test_any_other_build_error_keeps_its_text_and_chain(monkeypatch: pytest.MonkeyPatch) -> None:
    """The control: a ValueError that holds no codec error is kept as before."""
    error = ValueError("[store].synthetic_setting is not valid")
    monkeypatch.setattr(
        store_base,
        "resolve_key_provider",
        lambda settings, posture=None: _CodecErrorProvider(error),
    )
    with pytest.raises(StoreCipherConfigError) as caught:
        build_store_cipher(StoreSettings())
    assert str(caught.value) == str(error)
    assert caught.value.__cause__ is error


@pytest.mark.parametrize("command", _KEY_REFUSING_COMMANDS)
def test_the_four_commands_print_no_byte_of_the_key(
    command: str,
    key_file: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The commands the row names: exit 2, could not start, and no byte of the key printed."""
    db = key_file.parent / "keyed.db"
    _keyed_chain(db, generate_key())
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY_FILE", str(key_file))
    rc = main(_argv(command, db, key_file.parent))
    captured = capsys.readouterr()
    _assert_no_key_byte(captured.out + captured.err)
    assert rc == 2, (captured.out, captured.err)
    assert "not ASCII" in captured.out + captured.err


# --- item 3: a key arm on backup, restore-verify and restore -----------------------------------


def _backup_argv(tmp: Path) -> list[str]:
    return _argv("backup", tmp / "keyed.db", tmp)


def _archive(tmp: Path) -> str:
    """An archive file the commands never read: the key is resolved first."""
    archive = tmp / "synthetic.mfbak"
    archive.write_bytes(b"not read: the key is resolved first")
    return str(archive)


def _restore_verify_argv(tmp: Path) -> list[str]:
    return ["restore-verify", _archive(tmp), "--db", str(tmp / "keyed.db"), "--json"]


def _restore_argv(tmp: Path) -> list[str]:
    return ["restore", _archive(tmp), "--to", str(tmp / "restored.db"), "--json"]


@pytest.mark.parametrize(
    "argv",
    [_backup_argv, _restore_verify_argv, _restore_argv],
    ids=["backup", "restore-verify", "restore"],
)
def test_a_key_that_does_not_resolve_is_could_not_start(
    argv: Callable[[Path], list[str]],
    key_file: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Each reached the dispatch floor and exited 1, which restore-verify gives a FAIL."""
    _keyed_chain(key_file.parent / "keyed.db", generate_key())
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY_FILE", str(key_file))
    rc = main(argv(key_file.parent))
    captured = capsys.readouterr()
    assert rc == 2, (captured.out, captured.err)
    assert "the store key could not be resolved" in captured.out, captured.out
    _assert_no_key_byte(captured.out + captured.err)


def _raising(error: BaseException) -> Callable[..., Any]:
    """A stand-in for a client build or a mount that raises ``error``."""

    def _raise(*args: object, **kwargs: object) -> Any:
        raise error

    return _raise


@pytest.fixture
def vault_key_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """The variables `VaultKeyProvider.active_key` reads before it builds the client."""
    monkeypatch.setenv("MEFOR_STORE_VAULT_TRANSIT_KEY", "synthetic-kek")
    monkeypatch.setenv("MEFOR_STORE_VAULT_WRAPPED_DEK", "vault:v1:synthetic")
    monkeypatch.setenv("MEFOR_STORE_VAULT_ADDR", f"https://{_HOST}:8200")
    monkeypatch.setenv("MEFOR_STORE_VAULT_TOKEN", "s.synthetic-token")


@pytest.mark.parametrize(
    "error",
    [
        ValueError("synthetic TLS suite refusal"),
        OSError("synthetic CA load failure"),
        re.error("synthetic pattern error"),
    ],
    ids=["ValueError", "OSError", "re.error"],
)
def test_a_vault_client_that_cannot_be_built_is_a_key_provider_error(
    error: Exception, vault_key_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    from messagefoundry.store import keyprovider_vault

    monkeypatch.setattr(keyprovider_vault, "_build_client", _raising(error))
    with pytest.raises(KeyProviderError) as caught:
        keyprovider_vault.VaultKeyProvider(StoreSettings()).active_key()
    text = str(caught.value)
    assert "the Vault client could not be built" in text and str(error) in text, text
    assert "envelope-decrypt" not in text, "a configuration refusal read as a Vault-side failure"


def test_a_codec_error_from_the_vault_client_build_names_no_byte(
    vault_key_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    from messagefoundry.store import keyprovider_vault

    monkeypatch.setattr(keyprovider_vault, "_build_client", _raising(_decode_error()))
    with pytest.raises(KeyProviderError) as caught:
        keyprovider_vault.VaultKeyProvider(StoreSettings()).active_key()
    _assert_no_key_byte(_whole(caught.value))


def test_a_key_provider_error_from_the_build_passes_through(
    vault_key_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: the build's own fail-closed type is not wrapped a second time."""
    from messagefoundry.store import keyprovider_vault

    own = KeyProviderError("synthetic: the build's own refusal")

    monkeypatch.setattr(keyprovider_vault, "_build_client", _raising(own))
    with pytest.raises(KeyProviderError) as caught:
        keyprovider_vault.VaultKeyProvider(StoreSettings()).active_key()
    assert caught.value is own


# --- item 2: only the marked refusal keeps its text ----------------------------------------------


def _host_echoing() -> InsecureHopRefused:
    return InsecureHopRefused(f"synthetic hop to {_HOST}: refused")


@_vault
def test_the_marker_check_takes_exactly_the_marked_type() -> None:
    from messagefoundry.transports.strict_requests import VaultHopRefused

    class _Elsewhere(VaultHopRefused):
        pass

    assert is_vault_hop_refusal(VaultHopRefused("Vault test hop: fixed text"))
    assert not is_vault_hop_refusal(_host_echoing())
    assert not is_vault_hop_refusal(_Elsewhere("Vault test hop: fixed text"))
    assert not is_vault_hop_refusal(None)


@_vault
@pytest.mark.parametrize("marked", [True, False], ids=["marked", "base-type"])
@pytest.mark.parametrize("hop", ["store", "secrets"])
def test_a_vault_client_build_keeps_only_the_marked_refusal_text(
    hop: str, marked: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    import messagefoundry.transports.strict_requests as strict_requests
    from messagefoundry.config import secretprovider_vault
    from messagefoundry.config.secretprovider import SecretProviderError
    from messagefoundry.store import keyprovider_vault

    refusal = (
        strict_requests.VaultHopRefused("Vault test hop: fixed text") if marked else _host_echoing()
    )
    monkeypatch.setattr(strict_requests, "mount_strict_reply_adapter", _raising(refusal))
    module: Any = keyprovider_vault if hop == "store" else secretprovider_vault
    expected: type[Exception] = KeyProviderError if hop == "store" else SecretProviderError
    with pytest.raises(expected) as caught:
        module._build_client(f"https://{_HOST}:8200", "s.synthetic-token", revocation_attested=True)
    text = str(caught.value)
    if marked:
        assert text == "Vault test hop: fixed text"
    else:
        assert _HOST not in text and "InsecureHopRefused" in text, text
    assert caught.value.__cause__ is refusal


@_vault
@pytest.mark.parametrize("marked", [True, False], ids=["marked", "base-type"])
def test_provision_admin_shows_only_a_marked_cause(
    marked: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    import messagefoundry.__main__ as cli
    import messagefoundry.auth.service as service
    from messagefoundry.config.secretprovider import SecretProviderError
    from messagefoundry.config.settings import ServiceSettings
    from messagefoundry.config.tls_policy import HopPosture
    from messagefoundry.transports.strict_requests import VaultHopRefused

    cause = VaultHopRefused("Vault test hop: fixed text") if marked else _host_echoing()

    def _raise(*args: object, **kwargs: object) -> None:
        raise SecretProviderError("synthetic") from cause

    monkeypatch.setattr(service, "AuthService", _raise)
    with pytest.raises(cli._ProvisionAuthRefused) as caught:
        cli._build_provision_auth_service(
            ServiceSettings(),
            object(),  # type: ignore[arg-type]
            posture=HopPosture(enforcing=True),
        )
    if marked:
        assert "Vault test hop: fixed text" in str(caught.value)
    else:
        assert str(caught.value) == cli._PROVISION_AUTH_REFUSALS["reference"]


@_vault
def test_the_vault_probe_keeps_only_the_marked_refusal_text() -> None:
    from messagefoundry.privilege_probes import _ad_why, _why
    from messagefoundry.transports.strict_requests import VaultHopRefused

    assert _why(VaultHopRefused("Vault test hop: fixed text")) == "Vault test hop: fixed text"
    assert _why(_host_echoing()) == "InsecureHopRefused"
    # The AD probe keeps the LDAPS guard's text, as provision-admin and serve print it.
    assert _ad_why(_host_echoing()) == str(_host_echoing())
