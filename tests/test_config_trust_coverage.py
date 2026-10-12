# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Which paths the config-source trust checks read (vault BACKLOG #2626 step 3, #2596 step 4).

The checks used to read the config directory and its ``*.py`` alone. A load also runs a matching
``__pycache__`` file in place of the source, and reads ``connections.toml`` and the code-set
tables, so a writer of any of those changed what ran while every vetted path stayed clean. These
tests pin the wider list and show a write grant on each new member refuses the load, on both arms.

The Windows tests replace the ctypes readers only, as ``tests/test_config_source_trust.py`` tier 3
does, so they run on every host. On win32 the suite's session fixture replaces the gate's own
call, so this module asks for it back.
"""

from __future__ import annotations

import logging
import os
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from messagefoundry.config.settings import (
    INSECURE_CONFIG_SOURCE_ESCAPE_ENV,
    SECURITY_ENFORCEMENT_ENV,
)
from messagefoundry.config.wiring import WiringError, config_source_trust_paths, load_config

#: Everyone, the principal the ``fake_windows_readers`` fixture grants write to.
_EVERYONE = "S-1-1-0"

#: The ``fake_windows_readers`` fixture: a predicate naming the writable paths in, paths read out.
FakeReaders = Callable[[Callable[[Path], bool]], list[Path]]

pytestmark = pytest.mark.usefixtures("real_config_source_readers")

_CACHE_FILE = f"cfg.{sys.implementation.cache_tag}.pyc"


def _write_tree(directory: Path) -> None:
    """A config directory with every member the trust list names, and one it must not."""
    (directory / "cfg.py").write_text(
        "from messagefoundry import outbound, File\noutbound('o', File(directory='./out'))\n",
        encoding="utf-8",
    )
    cache = directory / "__pycache__"
    cache.mkdir()
    (cache / _CACHE_FILE).write_bytes(b"")
    (directory / "connections.toml").write_text("", encoding="utf-8")
    codesets = directory / "codesets"
    codesets.mkdir()
    (codesets / "a.csv").write_text("code,display\n", encoding="utf-8")
    (codesets / "b.TOML").write_text("", encoding="utf-8")
    # The loader reads only .csv and .toml, so a note beside the tables is not on the list.
    (codesets / "README.md").write_text("notes\n", encoding="utf-8")


def test_the_list_names_the_cache_connections_and_code_sets(tmp_path: Path) -> None:
    _write_tree(tmp_path)
    assert config_source_trust_paths(tmp_path) == [
        tmp_path,
        tmp_path / "cfg.py",
        tmp_path / "__pycache__",
        tmp_path / "__pycache__" / _CACHE_FILE,
        tmp_path / "connections.toml",
        tmp_path / "codesets",
        tmp_path / "codesets" / "a.csv",
        tmp_path / "codesets" / "b.TOML",
    ]


def test_a_bare_directory_lists_only_itself_and_its_modules(tmp_path: Path) -> None:
    """Control for the test above: the optional members appear only when they exist."""
    (tmp_path / "cfg.py").write_text("", encoding="utf-8")
    assert config_source_trust_paths(tmp_path) == [tmp_path, tmp_path / "cfg.py"]


def test_windows_reads_every_listed_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_windows_readers: FakeReaders
) -> None:
    """Positive control for the refusals below: a clean read of the whole tree loads."""
    monkeypatch.delenv(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, raising=False)
    _write_tree(tmp_path)
    expected = config_source_trust_paths(tmp_path)
    seen = fake_windows_readers(lambda _path: False)
    # The empty cache file is not a valid .pyc, so the source loader recompiles cfg.py.
    assert "o" in load_config(tmp_path).outbound
    assert seen == expected


@pytest.mark.parametrize(
    "member", ["__pycache__", _CACHE_FILE, "connections.toml", "codesets", "a.csv"]
)
def test_windows_refuses_a_writable_member(
    member: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fake_windows_readers: FakeReaders,
) -> None:
    monkeypatch.delenv(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, raising=False)
    _write_tree(tmp_path)
    fake_windows_readers(lambda path: path.name == member)
    with pytest.raises(WiringError, match="writable-by-others path") as excinfo:
        load_config(tmp_path)
    assert member in str(excinfo.value)
    assert _EVERYONE in str(excinfo.value)


def test_the_escape_downgrades_a_writable_cache_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    fake_windows_readers: FakeReaders,
) -> None:
    """The new members go through the same refusal, so the clamped escape covers them too."""
    monkeypatch.setenv(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, "1")
    monkeypatch.setenv(SECURITY_ENFORCEMENT_ENV, "warn")
    _write_tree(tmp_path)
    fake_windows_readers(lambda path: path.name == _CACHE_FILE)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.config.wiring"):
        assert "o" in load_config(tmp_path).outbound
    assert any(
        _CACHE_FILE in r.getMessage() and "dev/test override" in r.getMessage()
        for r in caplog.records
    )


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits")
@pytest.mark.parametrize(
    "relative",
    [Path("__pycache__") / _CACHE_FILE, Path("connections.toml"), Path("codesets") / "a.csv"],
)
def test_posix_refuses_a_group_writable_member(
    relative: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(INSECURE_CONFIG_SOURCE_ESCAPE_ENV, raising=False)
    _write_tree(tmp_path)
    (tmp_path / relative).chmod(0o664)
    with pytest.raises(WiringError, match="group/world-writable path") as excinfo:
        load_config(tmp_path)
    assert str(tmp_path / relative) in str(excinfo.value)
