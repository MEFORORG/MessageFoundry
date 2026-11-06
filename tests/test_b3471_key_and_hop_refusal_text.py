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

BACKLOG #4882, the routes engine PR 2662 left open: a codec error on any link of a build error,
whatever the error's class, leaves no byte in the refusal; and the store open and
``provision-admin`` print such a refusal with no byte. BACKLOG #4883, its ``_ad_why`` item: the AD
probe keeps only the LDAPS revocation guard's own refusal whole.

All key bytes, hosts and tokens here are synthetic. Severity is conditional (CLAUDE.md section 0).
"""

from __future__ import annotations

import re
import traceback
from collections.abc import Callable, Sequence
from pathlib import Path
from types import SimpleNamespace
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
#: A store key with one character that is not ASCII, the same code point as that byte.
_NON_ASCII_KEY = "c3ludGhl×dGljLWtleQ=="
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


def _with_provider(monkeypatch: pytest.MonkeyPatch, error: Exception) -> None:
    """Every store key resolution raises ``error``."""
    monkeypatch.setattr(
        store_base,
        "resolve_key_provider",
        lambda settings, posture=None: _CodecErrorProvider(error),
    )


@pytest.mark.parametrize(
    "error",
    [_decode_error(), ValueError("wrapped", _decode_error())],
    ids=["codec-error", "holds-a-codec-error"],
)
def test_build_store_cipher_renders_a_codec_error_without_its_bytes(
    error: Exception, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Any key source, not only DPAPI: the build renders the codec error and does not chain it."""
    _with_provider(monkeypatch, error)
    with pytest.raises(StoreCipherConfigError) as caught:
        build_store_cipher(StoreSettings())
    _assert_no_key_byte(_whole(caught.value))
    assert caught.value.__cause__ is None and caught.value.__context__ is None


def test_any_other_build_error_keeps_its_text_and_chain(monkeypatch: pytest.MonkeyPatch) -> None:
    """The control: a ValueError that holds no codec error is kept as before."""
    error = ValueError("[store].synthetic_setting is not valid")
    _with_provider(monkeypatch, error)
    with pytest.raises(StoreCipherConfigError) as caught:
        build_store_cipher(StoreSettings())
    assert str(caught.value) == str(error)
    assert caught.value.__cause__ is error


def test_a_key_with_a_character_that_is_not_ascii_leaves_no_codec_error_on_the_chain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The base64 decode of such a key failed with a UnicodeEncodeError as its context, which
    names the character and holds the whole key; the refusal carried it on its chain."""
    monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY_FILE", raising=False)
    with pytest.raises(StoreCipherConfigError) as caught:
        build_store_cipher(StoreSettings(encryption_key=_NON_ASCII_KEY))
    assert "must be valid base64" in str(caught.value)
    _assert_no_key_byte(_whole(caught.value))
    link: BaseException | None = caught.value
    while link is not None:
        assert not isinstance(link, UnicodeError), "a codec error is on the refusal's chain"
        link = link.__cause__ or link.__context__


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
    assert "the store key or cipher could not be resolved" in captured.out, captured.out
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


def test_a_client_build_hop_refusal_or_library_error_keeps_no_raw_text(
    vault_key_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unmarked hop refusal is named by its type, and an OSError is rendered by safe_exc, which
    keeps the type and bounds the text; neither is printed as it was raised."""
    from messagefoundry.store import keyprovider_vault

    monkeypatch.setattr(keyprovider_vault, "_build_client", _raising(_host_echoing()))
    with pytest.raises(KeyProviderError) as caught:
        keyprovider_vault.VaultKeyProvider(StoreSettings()).active_key()
    assert _HOST not in str(caught.value) and "InsecureHopRefused" in str(caught.value)

    monkeypatch.setattr(keyprovider_vault, "_build_client", _raising(OSError("x" * 500)))
    with pytest.raises(KeyProviderError) as caught:
        keyprovider_vault.VaultKeyProvider(StoreSettings()).active_key()
    assert "OSError" in str(caught.value) and "x" * 500 not in str(caught.value)


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
        assert _HOST not in str(caught.value) and "InsecureHopRefused" in str(caught.value)


@_vault
def test_the_vault_probe_keeps_only_the_marked_refusal_text() -> None:
    from messagefoundry.privilege_probes import _ad_why, _why
    from messagefoundry.transports.strict_requests import VaultHopRefused

    assert _why(VaultHopRefused("Vault test hop: fixed text")) == "Vault test hop: fixed text"
    assert _why(_host_echoing()) == "InsecureHopRefused"
    # BACKLOG #4883: the AD probe keeps only the LDAPS guard's own refusal whole, so a hop refusal
    # it did not raise reads by its type, as on the Vault probe.
    assert _ad_why(_host_echoing()) == "InsecureHopRefused"


# --- BACKLOG #4883, the `_ad_why` item: only the LDAPS guard's refusal keeps its text -----------


def test_the_ad_probe_keeps_the_ldaps_guard_refusal_whole(monkeypatch: pytest.MonkeyPatch) -> None:
    """The control: the guard's own refusal, raised inside ``_refuse_ad_revocation``."""
    from messagefoundry.auth import ldap
    from messagefoundry.config.settings import AuthSettings
    from messagefoundry.config.tls_policy import RevocationHopGuard
    from messagefoundry.privilege_probes import _ad_why

    monkeypatch.setattr(RevocationHopGuard, "capture", _raising(_host_echoing()))
    tls: Any = SimpleNamespace(handshake_context=lambda: None)
    with pytest.raises(InsecureHopRefused) as caught:
        ldap._refuse_ad_revocation(
            AuthSettings(ad_server="ldaps://dc.synthetic.test:636"), tls, None
        )
    assert _ad_why(caught.value) == str(_host_echoing())


def test_a_hop_refusal_from_the_bind_password_resolution_keeps_no_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A hop refusal the AD probe meets past the guard, here from resolving a Vault-held bind
    password, is named by its type, so the Vault host it names is not printed."""
    from messagefoundry.auth import ldap
    from messagefoundry.privilege_probes import read_ldap_bind
    from tests.test_vault_ldap_privilege_probes import _ad_service_settings

    monkeypatch.setattr(ldap, "resolve_connector_secret", _raising(_host_echoing()))
    reading = read_ldap_bind(_ad_service_settings(), None)
    assert reading.bound is False
    assert reading.problem is not None and "InsecureHopRefused" in reading.problem, reading
    assert _HOST not in reading.problem, reading.problem


# --- BACKLOG #4882: build_store_cipher routes PR 2662 left open ---------------------------------


def _built_from[E: Exception](error: UnicodeDecodeError, kind: type[E]) -> E:
    """A ``kind`` whose text quotes ``error``, raised from it."""
    try:
        raise kind(f"synthetic key source refused: {error}") from error
    except kind as exc:
        return exc


def _context_beside_cause(error: UnicodeDecodeError) -> ValueError:
    """A ValueError whose text quotes ``error``, which is its context; its cause is plain."""
    try:
        try:
            raise error
        except UnicodeDecodeError as inner:
            raise ValueError(f"synthetic: {inner}") from ValueError("synthetic plain cause")
    except ValueError as exc:
        return exc


def _group_holding(error: UnicodeDecodeError) -> ValueError:
    """A ValueError whose context is a group with the codec error as a member."""
    try:
        try:
            raise ExceptionGroup("synthetic", [error])
        except ExceptionGroup:
            raise ValueError("synthetic: the key source failed")  # noqa: B904 -- the context is the point
    except ValueError as exc:
        return exc


#: The refusal's words for an error whose chain, not its own text, holds the codec error.
_CHAINED = "whose chain holds a codec error"


@pytest.mark.parametrize(
    "error",
    [
        _built_from(_decode_error(), ValueError),
        _context_beside_cause(_decode_error()),
        _group_holding(_decode_error()),
    ],
    ids=["text-built-from-a-chained-codec-error", "context-beside-a-cause", "group-member"],
)
def test_a_value_error_with_a_codec_error_on_any_link_prints_no_byte(
    error: ValueError, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Each held the byte in its own text or on a link the old walk did not read, and kept it."""
    assert any(spelling in _whole(error) for spelling in _BYTE_SPELLINGS), "the fixture holds none"
    _with_provider(monkeypatch, error)
    with pytest.raises(StoreCipherConfigError) as caught:
        build_store_cipher(StoreSettings())
    _assert_no_key_byte(_whole(caught.value))
    assert caught.value.__cause__ is None and caught.value.__context__ is None
    assert f"ValueError {_CHAINED}" in str(caught.value), str(caught.value)


@pytest.mark.parametrize("kind", [RuntimeError, KeyProviderError, DpapiError])
def test_a_runtime_error_that_chains_a_codec_error_prints_no_byte(
    kind: type[RuntimeError], monkeypatch: pytest.MonkeyPatch
) -> None:
    """It passed through untouched; it is raised as KeyProviderError, which every store open's
    caller already reports as a key that could not be resolved."""
    _with_provider(monkeypatch, _built_from(_decode_error(), kind))
    with pytest.raises(KeyProviderError) as caught:
        build_store_cipher(StoreSettings())
    _assert_no_key_byte(_whole(caught.value))
    assert caught.value.__cause__ is None and caught.value.__context__ is None
    assert f"{kind.__name__} {_CHAINED}" in str(caught.value), str(caught.value)


def test_a_runtime_error_with_no_codec_error_passes_through(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The control: the same object, untouched."""
    own = KeyProviderError("synthetic: the provider's own refusal")
    _with_provider(monkeypatch, own)
    with pytest.raises(KeyProviderError) as caught:
        build_store_cipher(StoreSettings())
    assert caught.value is own


def test_a_holder_of_another_class_is_named_by_its_class(monkeypatch: pytest.MonkeyPatch) -> None:
    """A DpapiError that holds the codec error names its class, so the refusal says what failed."""
    _with_provider(monkeypatch, DpapiError(_decode_error()))
    with pytest.raises(KeyProviderError) as caught:
        build_store_cipher(StoreSettings())
    _assert_no_key_byte(_whole(caught.value))
    assert str(caught.value).startswith("DpapiError: "), str(caught.value)


class _UnreadableReason(ValueError):
    """An error whose ``reason``, which the chain walk reads, raises."""

    @property
    def reason(self) -> object:
        raise KeyError("synthetic: reason cannot be read")


def test_a_chain_that_raises_as_it_is_read_is_refused_without_its_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The walk runs a link's own code; an error from it must not leave with the original as its
    context, which would carry the byte."""
    try:
        raise _UnreadableReason(f"synthetic: {_decode_error()}")
    except _UnreadableReason as exc:
        error = exc
    _with_provider(monkeypatch, error)
    with pytest.raises(StoreCipherConfigError) as caught:
        build_store_cipher(StoreSettings())
    _assert_no_key_byte(_whole(caught.value))
    assert "cannot be read whole" in str(caught.value), str(caught.value)


@pytest.mark.parametrize("resolve", ["resolve_active_key", "resolve_decrypt_keys"])
def test_the_key_seam_refuses_a_chained_codec_error_without_its_byte(
    resolve: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The callers that resolve the key without building the cipher: ``rotate-key`` through the
    first, ``restore`` and ``restore-verify`` through the second."""
    _with_provider(monkeypatch, _built_from(_decode_error(), KeyProviderError))
    with pytest.raises(KeyProviderError) as caught:
        getattr(store_base, resolve)(StoreSettings())
    _assert_no_key_byte(_whole(caught.value))
    assert caught.value.__cause__ is None and caught.value.__context__ is None
    assert f"KeyProviderError {_CHAINED}" in str(caught.value), str(caught.value)


def test_rotate_key_prints_no_byte_of_a_chained_codec_error(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    db = shell / "keyed.db"
    key = generate_key()
    _keyed_chain(db, key)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", key)
    _with_provider(monkeypatch, _built_from(_decode_error(), KeyProviderError))
    rc = main(_argv("rotate-key", db, shell))
    captured = capsys.readouterr()
    _assert_no_key_byte(captured.out + captured.err)
    assert rc == 2, (captured.out, captured.err)
    assert _CHAINED in captured.out + captured.err


def test_the_postgres_tls_wrap_reads_a_context_beside_a_cause() -> None:
    """``_codec_chain_reading`` is the PostgreSQL TLS wrap's test (BACKLOG #2532)."""
    reading = store_base._codec_chain_reading
    assert reading(_context_beside_cause(_decode_error())) == "from a codec error"
    assert reading(ValueError("synthetic plain")) is None


def _unreadable_reason() -> _UnreadableReason:
    """A raised ValueError whose own text names no codec error and whose chain cannot be read."""
    try:
        raise _UnreadableReason("synthetic: the CA file could not be judged")
    except _UnreadableReason as exc:
        return exc


def test_the_postgres_tls_wrap_says_a_chain_it_cannot_read_is_not_a_codec_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Round two of the review: a chain that cannot be read whole was refused as one "from a
    codec error", which no codec error made true. It keeps no text, and says what is true."""
    from messagefoundry.config.tls_policy import StoreTlsRefused
    from messagefoundry.store import postgres

    assert store_base._codec_chain_reading(_unreadable_reason()) == (
        "whose chain cannot be read whole"
    )
    monkeypatch.setattr(postgres, "_verifying_context", _raising(_unreadable_reason()))
    with pytest.raises(StoreTlsRefused) as caught:
        postgres._verifying_context_at_open(StoreSettings())
    text = str(caught.value)
    assert "_UnreadableReason whose chain cannot be read whole" in text, text
    assert "codec" not in text and "could not be judged" not in text, text
    assert caught.value.__cause__ is None and caught.value.__context__ is None


class _LazyRetiredKeys(Sequence[str]):
    """A retired keyring that decodes as it is read, so the codec error rises on iteration."""

    def __len__(self) -> int:
        return 1

    def __getitem__(self, index: Any) -> Any:
        if index:
            raise IndexError(index)
        raise _built_from(_decode_error(), KeyProviderError)


class _RetiredCodecProvider:
    def __init__(self, retired: Callable[[], Sequence[str]]) -> None:
        self._retired = retired

    def active_key(self) -> str | None:
        return generate_key()

    def retired_keys(self) -> Sequence[str]:
        return self._retired()


@pytest.mark.parametrize(
    "retired",
    [_raising(_built_from(_decode_error(), KeyProviderError)), _LazyRetiredKeys],
    ids=["retired-keys-raises", "retired-keys-decode-as-read"],
)
def test_the_keyring_refuses_a_codec_error_from_the_retired_keys(
    retired: Callable[[], Sequence[str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Round two of the review: the retired keys were iterated outside the refusing try."""
    monkeypatch.setattr(
        store_base,
        "resolve_key_provider",
        lambda settings, posture=None: _RetiredCodecProvider(retired),
    )
    with pytest.raises(KeyProviderError) as caught:
        store_base.resolve_decrypt_keys(StoreSettings())
    _assert_no_key_byte(_whole(caught.value))
    assert caught.value.__cause__ is None and caught.value.__context__ is None
    assert f"KeyProviderError {_CHAINED}" in str(caught.value), str(caught.value)


@pytest.mark.parametrize("command", _KEY_REFUSING_COMMANDS)
def test_the_store_open_refusal_prints_no_byte_of_a_chained_codec_error(
    command: str,
    shell: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``_open_store_or_refuse``, the route PR 2662 named as ``_open_store_or_refuse_the_key``:
    exit 2, and no byte, for a key source whose own text quotes the codec error."""
    db = shell / "keyed.db"
    key = generate_key()
    _keyed_chain(db, key)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", key)
    _with_provider(monkeypatch, _built_from(_decode_error(), KeyProviderError))
    rc = main(_argv(command, db, shell))
    captured = capsys.readouterr()
    _assert_no_key_byte(captured.out + captured.err)
    assert rc == 2, (captured.out, captured.err)
    assert _CHAINED in captured.out + captured.err


def test_provision_admin_prints_no_byte_of_a_chained_codec_error(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """``provision-admin``'s key arm, at its pre-check of an absent SQLite store: exit 2."""
    from tests.test_keyless_chain_every_command import _PASSWORD
    from tests.test_provision_first_administrator import _tty

    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    _with_provider(monkeypatch, _built_from(_decode_error(), KeyProviderError))
    _tty(monkeypatch, _PASSWORD, _PASSWORD)
    db = shell / "absent.db"
    rc = main(
        [
            "provision-admin",
            "--username",
            "site-admin",
            "--email",
            "ops@example.invalid",
            "--db",
            str(db),
            "--json",
        ]
    )
    captured = capsys.readouterr()
    _assert_no_key_byte(captured.out + captured.err)
    assert rc == 2, (captured.out, captured.err)
    assert _CHAINED in captured.out, captured.out
    assert not db.exists()


# --- The hold on engine PR 2818, item 2: a BaseException from the chain walk -------------------


class _InterruptingReason(ValueError):
    """An error whose ``reason``, which the chain walk reads, raises ``interrupt``, a
    BaseException that ``except Exception`` does not catch."""

    interrupt: BaseException

    @property
    def reason(self) -> object:
        raise self.interrupt


def _interrupting(interrupt: BaseException) -> _InterruptingReason:
    """A raised error whose own text quotes the codec error, and whose walk raises ``interrupt``."""
    try:
        raise _InterruptingReason(f"synthetic key source refused: {_decode_error()}")
    except _InterruptingReason as exc:
        exc.interrupt = interrupt
        return exc


def _every_link(exc: BaseException) -> list[BaseException]:
    """``exc`` and every exception its cause, context, args and group members reach. It reads no
    ``reason`` attribute, so the fixture's own property does not fire here."""
    seen: list[BaseException] = []
    todo: list[BaseException] = [exc]
    while todo:
        link = todo.pop()
        if any(link is s for s in seen):
            continue
        seen.append(link)
        inner: list[object] = [link.__cause__, link.__context__, *link.args]
        if isinstance(link, BaseExceptionGroup):
            inner += link.exceptions
        todo += [i for i in inner if isinstance(i, BaseException)]
    return seen


def _call_the_postgres_wrap(error: Exception, monkeypatch: pytest.MonkeyPatch) -> None:
    from messagefoundry.store import postgres

    monkeypatch.setattr(postgres, "_verifying_context", _raising(error))
    postgres._verifying_context_at_open(StoreSettings())


@pytest.mark.parametrize(
    "make_interrupt",
    [KeyboardInterrupt, lambda: SystemExit(3)],
    ids=["keyboard-interrupt", "system-exit"],
)
@pytest.mark.parametrize(
    "entry",
    ["build_store_cipher", "resolve_active_key", "resolve_decrypt_keys", "postgres-tls-wrap"],
)
def test_a_base_exception_from_the_walk_leaves_without_the_codec_error_on_its_chain(
    entry: str, make_interrupt: Callable[[], BaseException], monkeypatch: pytest.MonkeyPatch
) -> None:
    """``except Exception`` in the walk does not catch it, so it left the refusing handler with
    the error it was judging as its context, and that error's text quotes the byte. It still
    propagates, as itself, with nothing of that error on its chain."""
    interrupt = make_interrupt()
    error = _interrupting(interrupt)
    assert any(spelling in _whole(error) for spelling in _BYTE_SPELLINGS), "the fixture holds none"
    with pytest.raises(type(interrupt)) as caught:
        if entry == "postgres-tls-wrap":
            _call_the_postgres_wrap(error, monkeypatch)
        else:
            _with_provider(monkeypatch, error)
            getattr(store_base, entry)(StoreSettings())
    _assert_left_unchained(caught.value, interrupt, error)


def _assert_left_unchained(
    escaped: BaseException, interrupt: BaseException, error: BaseException
) -> None:
    """``escaped`` is ``interrupt`` itself, and nothing its chain reaches is or quotes ``error``."""
    assert escaped is interrupt
    links = _every_link(escaped)
    assert not any(link is error for link in links), links
    for link in links:
        _assert_no_key_byte(repr(link))
        for arg in link.args:
            _assert_no_key_byte(repr(arg))
    _assert_no_key_byte("".join(traceback.format_exception(escaped)))


class _InterruptingDecodeError(UnicodeDecodeError):
    """A codec error whose ``start``, which its codec-safe rendering reads, raises ``interrupt``."""

    interrupt: BaseException

    @property
    def start(self) -> int:  # type: ignore[override]  # the read is the point
        raise self.interrupt


@pytest.mark.parametrize(
    "make_interrupt",
    [KeyboardInterrupt, lambda: SystemExit(3)],
    ids=["keyboard-interrupt", "system-exit"],
)
@pytest.mark.parametrize(
    "entry", ["build_store_cipher", "resolve_active_key", "resolve_decrypt_keys"]
)
def test_a_base_exception_from_rendering_the_codec_error_leaves_without_it(
    entry: str, make_interrupt: Callable[[], BaseException], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Round one of the repair's review: the walk stops at the codec error itself, and the
    interrupt rose later, from its rendering, still inside the refusing handler."""
    interrupt = make_interrupt()
    try:
        raise _InterruptingDecodeError("ascii", _KEY_BYTES, 18, 19, "ordinal not in range(128)")
    except _InterruptingDecodeError as exc:
        exc.interrupt = interrupt
        error = exc
    assert any(spelling in _whole(error) for spelling in _BYTE_SPELLINGS), "the fixture holds none"
    _with_provider(monkeypatch, error)
    with pytest.raises(type(interrupt)) as caught:
        getattr(store_base, entry)(StoreSettings())
    _assert_left_unchained(caught.value, interrupt, error)
