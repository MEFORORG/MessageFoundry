# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #8163, the residuals of #3471 that engine PR 2818 left on ``main``.

Item 2: the AD probe named any ``InsecureHopRefused`` whose traceback passed
``_refuse_ad_revocation`` as the LDAPS guard's refusal, so one the TLS context factory raised read
as the guard's, with the guard's remedy. Only the guard's own call counts now.

All material is synthetic. No PHI.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from messagefoundry.config.tls_policy import InsecureHopRefused
from messagefoundry.store.crypto import generate_key
from messagefoundry.store.keyprovider import KeyProviderError
from tests import test_b3471_key_and_hop_refusal_text as _b3471
from tests.test_b3471_key_and_hop_refusal_text import (
    _HOST,
    _assert_no_key_byte,
    _decode_error,
    _escaping,
    _host_echoing,
)
from tests.test_keyless_chain_every_command import _keyed_chain

# --- item 2: only the guard's own call is the guard's refusal -------------------------------------


def test_a_hop_refusal_from_the_tls_context_is_not_named_as_the_guards() -> None:
    """Red before the fix: the refusal passed through ``_refuse_ad_revocation``, so the probe gave
    the guard's fixed text and its CRL remedy for an error the guard never raised."""
    from messagefoundry.auth import ldap
    from messagefoundry.config.settings import AuthSettings
    from messagefoundry.privilege_probes import _AD_GUARD_REFUSAL, _ad_why

    def context() -> None:
        raise _host_echoing()

    tls: Any = SimpleNamespace(handshake_context=context)
    settings = AuthSettings(ad_server="ldaps://dc.synthetic.test:636")
    refusal = _escaping(lambda: ldap._refuse_ad_revocation(settings, tls, None))
    assert type(refusal) is InsecureHopRefused, type(refusal)
    text = _ad_why(refusal)
    assert text != _AD_GUARD_REFUSAL
    assert text == "InsecureHopRefused"
    assert _HOST not in text


# --- item 5, the `_why` half: the probe reads no text by running the error's code ---------------


class _KeyErrorStrRaises(KeyProviderError):
    def __str__(self) -> str:
        raise RuntimeError("synthetic: __str__ ran")


class _KeyErrorStrSaysTheByte(KeyProviderError):
    def __str__(self) -> str:
        return "synthetic key source refused: byte 0xd7 (\xd7)"


def _probe_why(exc: BaseException) -> str:
    from messagefoundry.privilege_probes import _why

    try:
        return _why(exc)
    except Exception as escaped:  # noqa: BLE001 -- an escape is the defect measured
        pytest.fail(f"_why let {type(escaped).__name__} escape in place of a problem text")


def test_the_probe_text_survives_a_str_that_raises() -> None:
    """Red before the fix: ``_why`` called the error's ``__str__``, so it raised out of the
    probe's handler in place of a problem text."""
    assert _probe_why(_KeyErrorStrRaises("[store].synthetic is not set")) == "_KeyErrorStrRaises"


def test_the_probe_text_is_not_read_from_a_str_of_the_errors_own() -> None:
    """A fail-closed class's subclass whose ``__str__`` says a byte is named by its type alone."""
    text = _probe_why(_KeyErrorStrSaysTheByte("[store].synthetic is not set"))
    _assert_no_key_byte(text)
    assert text == "_KeyErrorStrSaysTheByte"


def test_the_probe_text_names_no_byte_of_a_codec_error_it_holds() -> None:
    """Red before the fix: ``str(KeyProviderError(codec_error))`` is the codec error's text, which
    names the byte it could not decode."""
    text = _probe_why(KeyProviderError(_decode_error()))
    _assert_no_key_byte(text)
    assert "KeyProviderError" in text


def test_the_probe_still_keeps_a_fail_closed_errors_own_text() -> None:
    """The control: a plain engine refusal still reads as its text."""
    assert _probe_why(KeyProviderError("[store].synthetic is not set")) == (
        "[store].synthetic is not set"
    )


# --- item 11: a key-seam hop refusal is a key that could not be resolved ------------------------

# Fixtures bound by name, so pytest applies them in this module too.
key_file = _b3471.key_file
shell = _b3471.shell


@pytest.mark.parametrize("entry", ["resolve_active_key", "resolve_decrypt_keys"])
def test_a_key_seam_hop_refusal_is_caught_by_every_cli_key_arm(
    entry: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Red before the fix: the key seam raised a plain ``InsecureHopRefused``, which is not one of
    the CLI's key-unresolved classes, so a key arm that catches only those missed it. It stays a
    hop refusal, so a caller that reports one still does."""
    from messagefoundry import __main__ as cli
    from messagefoundry.config.settings import StoreSettings
    from messagefoundry.store import base as store_base

    _b3471._with_provider(monkeypatch, _host_echoing())
    escaped = _escaping(lambda: getattr(store_base, entry)(StoreSettings()))
    assert isinstance(escaped, InsecureHopRefused), type(escaped)
    assert isinstance(escaped, cli._key_unresolved()), type(escaped)
    assert _HOST not in str(escaped)


@pytest.mark.parametrize(
    "argv",
    [_b3471._restore_verify_argv, _b3471._restore_argv],
    ids=["restore-verify", "restore"],
)
def test_restore_and_restore_verify_exit_2_on_a_key_seam_hop_refusal(
    argv: Callable[[Path], list[str]],
    key_file: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Red before the fix: each reached the dispatch floor and exited 1."""
    from messagefoundry.__main__ import main

    _keyed_chain(key_file.parent / "keyed.db", generate_key())
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY_FILE", str(key_file))
    _b3471._with_provider(monkeypatch, _host_echoing())
    rc = main(argv(key_file.parent))
    captured = capsys.readouterr()
    assert rc == 2, (captured.out, captured.err)
    assert "the store key or cipher could not be resolved" in captured.out, captured.out
    assert _HOST not in captured.out + captured.err
