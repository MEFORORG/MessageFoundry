# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #4878: ``dr_backup`` decoded each store key with a bare ``base64.b64decode`` at three
sites: the backup's ``_resolve_key``, ``run_restore_verify`` and ``run_restore``.

Measured before the fix, on Windows, with the synthetic keys below set in
``MEFOR_STORE_ENCRYPTION_KEY``: ``restore-verify`` and ``restore`` each exited 1 through the
last-resort handler. For the key with a character that is not ASCII the raised ``ValueError``
chained a ``UnicodeEncodeError`` naming that character and its position, and holding the whole key
as its ``object``. Each site now decodes by the rule ``open_store`` applies and raises
``StoreCipherConfigError`` with fixed text and no chain, and both commands exit 2, "could not
start".

Every key here is synthetic. Severity is conditional (CLAUDE.md section 0)."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.config.settings import BackupSettings, StoreSettings
from messagefoundry.pipeline import dr_backup
from messagefoundry.pipeline.dr_backup import BackupRunner
from messagefoundry.store.base import StoreCipherConfigError

#: A store key with one character that is not ASCII.
_NON_ASCII_KEY = "c3ludGhlédGljLWtleQ=="
#: Every spelling of that character a codec error's text, its repr or a print could carry.
_CHAR_SPELLINGS = ("é", "\\xe9", "0xe9", "position 8")
#: A key that is ASCII but not base64.
_MALFORMED_KEY = "!!!not-base64"
_BAD_KEYS = pytest.mark.parametrize(
    "key", [_NON_ASCII_KEY, _MALFORMED_KEY], ids=["non-ascii", "malformed"]
)


def _assert_holds_no_key(exc: BaseException) -> None:
    """The refusal is the typed one, carries no chain, and no text in it spells the key."""
    assert isinstance(exc, StoreCipherConfigError)
    assert exc.__cause__ is None and exc.__context__ is None
    text = f"{exc} {exc!r}"
    assert not any(s in text for s in _CHAR_SPELLINGS), text
    assert _MALFORMED_KEY not in text


@_BAD_KEYS
def test_restore_verify_refuses_a_bad_key_without_its_bytes(key: str) -> None:
    with pytest.raises(StoreCipherConfigError) as caught:
        asyncio.run(
            dr_backup.run_restore_verify(
                "never-read.mfbak", store_settings=StoreSettings(path="x.db", encryption_key=key)
            )
        )
    _assert_holds_no_key(caught.value)


@_BAD_KEYS
def test_restore_refuses_a_bad_key_without_its_bytes(key: str) -> None:
    with pytest.raises(StoreCipherConfigError) as caught:
        asyncio.run(
            dr_backup.run_restore(
                "never-read.mfbak",
                dest_store_path="never-written.db",
                store_settings=StoreSettings(path="x.db", encryption_key=key),
            )
        )
    _assert_holds_no_key(caught.value)


@_BAD_KEYS
def test_the_backups_key_resolve_refuses_a_bad_key_without_its_bytes(key: str) -> None:
    runner = BackupRunner(
        None,  # type: ignore[arg-type]  # _resolve_key never touches the store
        BackupSettings(enabled=True, destination="never-used"),
        store_settings=StoreSettings(path="x.db", encryption_key=key),
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
@pytest.mark.parametrize("command", ["restore-verify", "restore"])
def test_the_commands_exit_2_and_print_no_key_byte(
    command: str,
    key: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Each exited 1 through the last-resort handler before; now it is "could not start"."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", key)
    archive = tmp_path / "synthetic.mfbak"
    archive.write_bytes(b"not read: the key is resolved first")
    target = (
        ["--db", str(tmp_path / "x.db")]
        if command == "restore-verify"
        else ["--to", str(tmp_path / "restored.db")]
    )
    rc = main([command, str(archive), *target, "--json"])
    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert rc == 2, output
    assert "the store key or cipher could not be resolved" in output, output
    assert not any(s in output for s in _CHAR_SPELLINGS), output
    assert _MALFORMED_KEY not in output
    assert not (tmp_path / "restored.db").exists()
