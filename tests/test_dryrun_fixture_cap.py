# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The dry-run fixture reader refuses an over-cap file (ASVS 5.1.1, BACKLOG #1127).

The IDE extension's Test Bench and Steps view pick a local file and hand its path to
``messagefoundry dryrun``, and ``messagefoundry check`` reads its fixtures through the same module.
Owner ruling 2026-09-23: those pickers are 5.1.1 upload features, so the read needs a stated maximum.
The cap is the engine's per-message ceiling, which is also the File source's per-file default.

The boundary tests lower the cap with ``monkeypatch`` so they need no 16 MiB file on disk.
PHI-free: every fixture here is synthetic.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry.parsing.peek import DEFAULT_MAX_MESSAGE_BYTES
from messagefoundry.pipeline import dryrun
from messagefoundry.transports.file import DEFAULT_MAX_FILE_BYTES

_MSG = b"MSH|^~\\&|A|B|C|D|20260101000000||ADT^A01|1|P|2.5\r"


def _fixture(tmp_path: Path, size: int, name: str = "big.hl7") -> Path:
    path = tmp_path / name
    path.write_bytes(_MSG + b"X" * (size - len(_MSG)))
    return path


def test_the_cap_is_the_per_message_ceiling_and_the_file_sources_per_file_cap() -> None:
    assert dryrun.MAX_FIXTURE_FILE_BYTES == DEFAULT_MAX_MESSAGE_BYTES
    assert dryrun.MAX_FIXTURE_FILE_BYTES == DEFAULT_MAX_FILE_BYTES


@pytest.mark.parametrize("reader", ["read_messages", "read_message_sets"])
def test_a_file_over_the_cap_is_refused_with_a_clear_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reader: str
) -> None:
    monkeypatch.setattr(dryrun, "MAX_FIXTURE_FILE_BYTES", 64, raising=False)
    path = _fixture(tmp_path, 65)
    with pytest.raises(ValueError, match=r"big\.hl7 is over the 64-byte dry-run file cap"):
        if reader == "read_messages":
            dryrun.read_messages([str(path)])
        else:
            dryrun.read_message_sets(path, [])


@pytest.mark.parametrize("reader", ["read_messages", "read_message_sets"])
def test_a_file_at_the_cap_is_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reader: str
) -> None:
    monkeypatch.setattr(dryrun, "MAX_FIXTURE_FILE_BYTES", 64, raising=False)
    path = _fixture(tmp_path, 64)
    if reader == "read_messages":
        assert dryrun.read_messages([str(path)])[0][2] == path.read_bytes()
    else:
        assert dryrun.read_message_sets(path, [])[0][2] == path.read_bytes()


def test_a_directory_with_one_over_cap_file_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(dryrun, "MAX_FIXTURE_FILE_BYTES", 64, raising=False)
    _fixture(tmp_path, 40, "a_small.hl7")
    _fixture(tmp_path, 65, "b_big.hl7")
    with pytest.raises(ValueError, match="b_big.hl7"):
        dryrun.read_messages([str(tmp_path)])
    with pytest.raises(ValueError, match="b_big.hl7"):
        dryrun.read_message_sets(tmp_path, [])


def test_check_reports_an_over_cap_fixture_as_a_failed_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``messagefoundry check`` must fail its dryrun gate with the message, not crash."""
    from messagefoundry.checks import _check_dryrun

    monkeypatch.setattr(dryrun, "MAX_FIXTURE_FILE_BYTES", 64, raising=False)
    config = tmp_path / "config"
    config.mkdir()
    (config / "graph.py").write_text(
        "from messagefoundry import MLLP, handler, inbound, router\n"
        "inbound('IB_T', MLLP(port=2575), router='r')\n"
        "@router('r')\n"
        "def r(msg):\n    return []\n",
        encoding="utf-8",
    )
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    _fixture(fixtures, 65)
    result = _check_dryrun(config, fixtures)
    assert result.ok is False
    assert "dry-run file cap" in result.detail
