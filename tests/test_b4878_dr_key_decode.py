# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #4878: ``dr_backup`` decoded each store key with a bare ``base64.b64decode`` at three
sites: the backup's ``_resolve_key``, ``run_restore_verify`` and ``run_restore``.

Measured before the fix, on Windows, with a synthetic key set in ``MEFOR_STORE_ENCRYPTION_KEY``:
``restore-verify`` and ``restore`` each exited 1 through the last-resort handler, for a key that is
not base64 and for one with a character that is not ASCII. For the second, the raised
``ValueError`` chained a ``UnicodeEncodeError`` naming that character and its position, and holding
the whole key as its ``object``. Each site now decodes by the rule ``open_store`` applies and
raises ``StoreCipherConfigError`` with fixed text and no chain, and both commands exit 2, "could
not start".

Every key here is synthetic. Severity is conditional (CLAUDE.md section 0)."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.config.settings import BackupSettings, StoreSettings
from messagefoundry.pipeline import dr_backup
from messagefoundry.pipeline.dr_backup import BackupRunner
from messagefoundry.store.base import StoreCipherConfigError
from tests.test_b3471_key_and_hop_refusal_text import (
    _NON_ASCII_KEY,
    _assert_no_key_byte,
    _restore_argv,
    _restore_verify_argv,
    _whole,
)

#: A key that is ASCII but not base64.
_MALFORMED_KEY = "!!!not-base64"
_BAD_KEYS = pytest.mark.parametrize(
    "key", [_NON_ASCII_KEY, _MALFORMED_KEY], ids=["non-ascii", "malformed"]
)


def _assert_holds_no_key(exc: BaseException) -> None:
    """The refusal is the typed one, carries no chain, and nothing it could print spells the key."""
    assert isinstance(exc, StoreCipherConfigError)
    assert exc.__cause__ is None and exc.__context__ is None
    text = _whole(exc) + repr(exc)
    _assert_no_key_byte(text)
    assert _MALFORMED_KEY not in text


def _settings(key: str) -> StoreSettings:
    return StoreSettings(path="x.db", encryption_key=key)


@_BAD_KEYS
def test_restore_verify_refuses_a_bad_key_without_its_bytes(key: str) -> None:
    with pytest.raises(StoreCipherConfigError) as caught:
        asyncio.run(dr_backup.run_restore_verify("never-read.mfbak", store_settings=_settings(key)))
    _assert_holds_no_key(caught.value)


@_BAD_KEYS
def test_restore_refuses_a_bad_key_without_its_bytes(key: str) -> None:
    with pytest.raises(StoreCipherConfigError) as caught:
        asyncio.run(
            dr_backup.run_restore(
                "never-read.mfbak",
                dest_store_path="never-written.db",
                store_settings=_settings(key),
            )
        )
    _assert_holds_no_key(caught.value)


@_BAD_KEYS
def test_the_backups_key_resolve_refuses_a_bad_key_without_its_bytes(key: str) -> None:
    runner = BackupRunner(
        None,  # type: ignore[arg-type]  # _resolve_key never touches the store
        BackupSettings(enabled=True, destination="never-used"),
        store_settings=_settings(key),
        config_dir=None,
        instance="dev",
    )
    with pytest.raises(StoreCipherConfigError) as caught:
        runner._resolve_key()
    _assert_holds_no_key(caught.value)


def test_a_key_of_the_wrong_length_is_refused_too() -> None:
    """The rule ``open_store`` applies: valid base64 that is not 32 bytes is no store key."""
    with pytest.raises(StoreCipherConfigError, match="32 bytes"):
        dr_backup._decode_store_key("c3ludGhldGlj")


def test_a_good_key_still_decodes() -> None:
    """The control: a strict base64 key of 32 bytes decodes to them."""
    assert dr_backup._decode_store_key("A" * 43 + "=") == bytes(32)


@_BAD_KEYS
@pytest.mark.parametrize(
    "argv", [_restore_verify_argv, _restore_argv], ids=["restore-verify", "restore"]
)
def test_the_commands_exit_2_and_print_no_key_byte(
    argv: Callable[[Path], list[str]],
    key: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Each exited 1 through the last-resort handler before; now it is "could not start"."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", key)
    rc = main(argv(tmp_path))
    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert rc == 2, output
    assert "the store key or cipher could not be resolved" in output, output
    _assert_no_key_byte(output)
    assert _MALFORMED_KEY not in output
    assert not (tmp_path / "restored.db").exists()
