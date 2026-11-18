# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5334: a load never records a graph with no config-code digest, which the sandbox
worker comparison would skip. Only an unread module takes the digest away, and a load whose digest
is unavailable is refused."""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry.config import wiring
from messagefoundry.config.snapshot import ConfigSnapshot
from messagefoundry.config.wiring import WiringError, config_code_digest, load_snapshot

_MODULE = b"X = 1\n"


def _snapshot(directory: Path, unreadable: tuple[str, ...]) -> ConfigSnapshot:
    return ConfigSnapshot(
        directory=directory,
        files={"graph.py": _MODULE},
        unreadable=unreadable,
        value_file=directory / "values.py",
    )


def test_an_unread_value_file_named_py_keeps_the_digest(tmp_path: Path) -> None:
    held = config_code_digest(_snapshot(tmp_path, ()))
    assert held is not None  # the control
    snapshot = _snapshot(tmp_path, ("@value-file/values.py",))
    assert config_code_digest(snapshot) == held
    assert load_snapshot(snapshot, allow_empty=True).code_digest == held


def test_an_unread_module_still_takes_the_digest_away(tmp_path: Path) -> None:
    assert config_code_digest(_snapshot(tmp_path, ("other.py",))) is None


def test_a_load_with_no_digest_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    snapshot = _snapshot(tmp_path, ())
    assert load_snapshot(snapshot, allow_empty=True).code_digest is not None  # the control
    monkeypatch.setattr(wiring, "config_code_digest", lambda source: None)
    with pytest.raises(WiringError, match="digest could not be computed"):
        load_snapshot(snapshot, allow_empty=True)
