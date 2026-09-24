# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The dry-run fixture reader refuses an over-cap or unreadable file (ASVS 5.1.1, BACKLOG #1127).

Why the cap exists and what it is: the comment on ``MAX_FIXTURE_FILE_BYTES`` in
``messagefoundry/pipeline/dryrun.py``. The boundary tests lower that constant with ``monkeypatch``
so they need no 16 MiB file on disk. PHI-free: every fixture here is synthetic.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from messagefoundry.parsing.peek import DEFAULT_MAX_MESSAGE_BYTES
from messagefoundry.pipeline import dryrun

_MSG = b"MSH|^~\\&|A|B|C|D|20260101000000||ADT^A01|1|P|2.5\r"

_GRAPH = (
    "from messagefoundry import MLLP, inbound, router\n"
    "inbound('IB_T', MLLP(port=2575), router='r'{extra})\n"
    "@router('r')\n"
    "def r(msg):\n    return []\n"
)


def _fixture(tmp_path: Path, size: int, name: str = "big.hl7") -> Path:
    assert size >= len(_MSG), "a fixture smaller than its MSH header cannot hit an exact size"
    path = tmp_path / name
    path.write_bytes(_MSG + b"X" * (size - len(_MSG)))
    return path


def _read(reader: str, path: Path, cap: int | None = None) -> bytes:
    if reader == "read_messages":
        return dryrun.read_messages([str(path)], cap=cap)[0][2]
    return dryrun.read_message_sets(path, [], cap=cap)[0][2]


def test_the_default_cap_is_the_per_message_ceiling() -> None:
    assert dryrun.MAX_FIXTURE_FILE_BYTES == DEFAULT_MAX_MESSAGE_BYTES
    assert dryrun.fixture_cap() == DEFAULT_MAX_MESSAGE_BYTES


@pytest.mark.parametrize("reader", ["read_messages", "read_message_sets"])
def test_a_file_over_the_cap_is_refused_with_a_clear_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reader: str
) -> None:
    monkeypatch.setattr(dryrun, "MAX_FIXTURE_FILE_BYTES", 64)
    path = _fixture(tmp_path, 65)
    with pytest.raises(ValueError, match=r"big\.hl7 is over the 64-byte dry-run file cap"):
        _read(reader, path)


@pytest.mark.parametrize("reader", ["read_messages", "read_message_sets"])
def test_a_file_at_the_cap_is_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reader: str
) -> None:
    monkeypatch.setattr(dryrun, "MAX_FIXTURE_FILE_BYTES", 64)
    path = _fixture(tmp_path, 64)
    assert _read(reader, path) == path.read_bytes()


@pytest.mark.parametrize("reader", ["read_messages", "read_message_sets"])
def test_an_explicit_cap_wins_over_the_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reader: str
) -> None:
    monkeypatch.setattr(dryrun, "MAX_FIXTURE_FILE_BYTES", 64)
    path = _fixture(tmp_path, 100)
    assert _read(reader, path, cap=100) == path.read_bytes()


def test_a_directory_with_one_over_cap_file_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(dryrun, "MAX_FIXTURE_FILE_BYTES", 64)
    _fixture(tmp_path, 50, "a_small.hl7")
    _fixture(tmp_path, 65, "b_big.hl7")
    with pytest.raises(ValueError, match="b_big.hl7"):
        dryrun.read_messages([str(tmp_path)])
    with pytest.raises(ValueError, match="b_big.hl7"):
        dryrun.read_message_sets(tmp_path, [])


def test_an_over_cap_file_is_never_read_whole(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The property the cap exists for: at most cap + 1 bytes are ever pulled off the file."""
    path = _fixture(tmp_path, 10_000)
    consumed: list[int] = []
    real_open = Path.open

    class _Counting:
        def __init__(self, fh: Any) -> None:
            self._fh = fh

        def __enter__(self) -> _Counting:
            return self

        def __exit__(self, *exc: object) -> None:
            self._fh.close()

        def fileno(self) -> int:
            return int(self._fh.fileno())

        def read(self, size: int = -1) -> bytes:
            data: bytes = self._fh.read(size)
            consumed.append(len(data))
            return data

    def _open(self: Path, *args: Any, **kwargs: Any) -> Any:
        fh = real_open(self, *args, **kwargs)
        return _Counting(fh) if self == path else fh

    monkeypatch.setattr(Path, "open", _open)
    with pytest.raises(ValueError, match="dry-run file cap"):
        dryrun.read_messages([str(path)], cap=64)
    assert sum(consumed) <= 65


def test_an_unreadable_fixture_is_a_value_error(tmp_path: Path) -> None:
    (tmp_path / "old.hl7").mkdir()  # a directory named like a fixture, matched by the *.hl7 glob
    with pytest.raises(ValueError, match=r"cannot read fixture .*old\.hl7"):
        dryrun.read_message_sets(tmp_path, [])


def _mkdir(path: Path) -> Path:
    path.mkdir()
    return path


def _config(tmp_path: Path, extra: str = "") -> Path:
    config = tmp_path / "config"
    config.mkdir()
    (config / "graph.py").write_text(_GRAPH.format(extra=extra), encoding="utf-8")
    return config


def test_a_streaming_inbound_raises_the_cap_to_its_max_message_bytes(tmp_path: Path) -> None:
    """A fixture the engine would admit must not be refused by its own preview (ADR 0105)."""
    from messagefoundry.config.wiring import load_config

    big = 64 * 1024 * 1024
    reg = load_config(_config(tmp_path, f", max_message_bytes={big}"))
    assert dryrun.fixture_cap(reg) == big
    assert (
        dryrun.fixture_cap(load_config(_config(_mkdir(tmp_path / "plain"))))
        == DEFAULT_MAX_MESSAGE_BYTES
    )


def test_check_reports_an_over_cap_fixture_as_a_failed_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``messagefoundry check`` must fail its dryrun gate with the message, not crash."""
    from messagefoundry.checks import _check_dryrun

    monkeypatch.setattr(dryrun, "MAX_FIXTURE_FILE_BYTES", 64)
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    _fixture(fixtures, 65)
    result = _check_dryrun(_config(tmp_path), fixtures)
    assert result.ok is False
    assert "dry-run file cap" in result.detail
