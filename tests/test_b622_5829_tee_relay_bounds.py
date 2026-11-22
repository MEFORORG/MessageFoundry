# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The tee relay refuses a non-positive retry count or shadow-queue bound (BACKLOG #5829).

A ``corepoint_attempts`` of zero or less would skip the forward loop, so an ACKed Epic message
would never reach Corepoint and the relay would fail on its "the loop ran" invariant instead of
tripping fail-closed. A ``mefor_queue_max`` of zero or less would make ``asyncio.Queue``
unbounded. Both must be refused at construction and at the CLI, before any listener starts.
"""

from __future__ import annotations

import pytest

from tee.__main__ import _build_parser
from tee.relay import RelayConfig

_BASE_ARGV = [
    "run",
    "--listen-epic",
    "127.0.0.1:6661",
    "--corepoint",
    "127.0.0.1:6662",
    "--mefor",
    "127.0.0.1:6663",
    "--db",
    "relay.db",
]


def _config(**overrides: int) -> RelayConfig:
    return RelayConfig(
        listen_epic=("127.0.0.1", 6661),
        corepoint=("127.0.0.1", 6662),
        mefor=("127.0.0.1", 6663),
        db_path="relay.db",
        **overrides,  # type: ignore[arg-type]
    )


@pytest.mark.parametrize("field", ["corepoint_attempts", "mefor_queue_max"])
@pytest.mark.parametrize("value", [0, -1])
def test_config_refuses_non_positive(field: str, value: int) -> None:
    with pytest.raises(ValueError, match=field):
        _config(**{field: value})


@pytest.mark.parametrize("field", ["corepoint_attempts", "mefor_queue_max"])
def test_config_refuses_bool(field: str) -> None:
    with pytest.raises(ValueError, match=field):
        _config(**{field: True})


def test_config_accepts_one() -> None:
    cfg = _config(corepoint_attempts=1, mefor_queue_max=1)
    assert cfg.corepoint_attempts == 1
    assert cfg.mefor_queue_max == 1


@pytest.mark.parametrize("flag", ["--corepoint-attempts", "--mefor-queue-max"])
@pytest.mark.parametrize("value", ["0", "-3", "1.5", "x"])
def test_cli_refuses_non_positive_integer(
    flag: str, value: str, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc:
        _build_parser().parse_args([*_BASE_ARGV, f"{flag}={value}"])
    assert exc.value.code == 2
    assert "positive integer" in capsys.readouterr().err


def test_cli_accepts_positive_integers() -> None:
    args = _build_parser().parse_args(
        [*_BASE_ARGV, "--corepoint-attempts", "1", "--mefor-queue-max", "5"]
    )
    assert args.corepoint_attempts == 1
    assert args.mefor_queue_max == 5
