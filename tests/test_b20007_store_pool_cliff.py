# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The ADR 0062 store-pool cliff is enforced before a shardcert run (BACKLOG #5953, S27-74).

``check_store_pool_size`` had no caller, so a ``--store-pool-size`` at or over ``POOL_SIZE_CLIFF`` ran
and measured a pool-thrash wall. Both shardcert halves now refuse it before the store reset unless
``force_store_pool_size`` is set. Unit tests over the loaded graph: no store, no fleet, no load.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import harness.load.shardcert as shardcert
from harness.load.coord import FileDropCoord
from harness.load.shardcert import (
    ENGINE_SETUP_FAILED,
    POOL_SIZE_CLIFF,
    StorePoolOverCliff,
    run_shardcert,
    run_shardcert_engine,
)


class _ReachedReset(Exception):
    """Raised by the stubbed store reset: the run got past the pool check."""


@pytest.fixture
def reset_calls(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    calls: list[int] = []

    async def fake_reset(env: object) -> None:
        calls.append(1)
        raise _ReachedReset

    monkeypatch.setattr(shardcert, "_reset_store", fake_reset)
    return calls


async def test_single_box_refuses_a_pool_at_the_cliff(reset_calls: list[int]) -> None:
    with pytest.raises(StorePoolOverCliff, match="--force-store-pool-size"):
        await run_shardcert(store_pool_size=POOL_SIZE_CLIFF)
    assert reset_calls == []


async def test_single_box_runs_a_forced_pool_at_the_cliff(reset_calls: list[int]) -> None:
    with pytest.raises(_ReachedReset):
        await run_shardcert(store_pool_size=POOL_SIZE_CLIFF, force_store_pool_size=True)
    assert reset_calls == [1]


async def test_single_box_runs_a_pool_below_the_cliff(reset_calls: list[int]) -> None:
    with pytest.raises(_ReachedReset):
        await run_shardcert(store_pool_size=POOL_SIZE_CLIFF - 1)


async def test_engine_half_refuses_a_pool_at_the_cliff_and_tells_the_drive(
    reset_calls: list[int], tmp_path: Path
) -> None:
    """The drive half is waiting for SHARDS_READY; ENGINE_SETUP_FAILED stops it at once."""
    coord = FileDropCoord(tmp_path / "coord", run_id="cliff")
    with pytest.raises(StorePoolOverCliff):
        await run_shardcert_engine(sink_port=1, coord=coord, store_pool_size=POOL_SIZE_CLIFF + 5)
    assert reset_calls == []
    failed = coord.read(ENGINE_SETUP_FAILED)
    assert failed is not None
    assert "cliff" in str(failed)


async def test_engine_half_runs_a_forced_pool_at_the_cliff(
    reset_calls: list[int], tmp_path: Path
) -> None:
    coord = FileDropCoord(tmp_path / "coord", run_id="forced")
    with pytest.raises(_ReachedReset):
        await run_shardcert_engine(
            sink_port=1, coord=coord, store_pool_size=POOL_SIZE_CLIFF, force_store_pool_size=True
        )
    assert coord.read(ENGINE_SETUP_FAILED) is None


def _cli_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in (
        "MEFOR_SHARDCERT_SHARDS",
        "MEFOR_SHARDCERT_LANES_PER_SHARD",
        "MEFOR_SHARDCERT_PERSISTENT",
        "MEFOR_SHARDCERT_ROUTING",
    ):
        monkeypatch.setenv(key, "")  # the CLI writes these; setenv restores them at teardown
    monkeypatch.setenv("MEFOR_STORE_BACKEND", "sqlserver")


def test_cli_refusal_is_a_setup_exit(
    monkeypatch: pytest.MonkeyPatch, reset_calls: list[int], capsys: pytest.CaptureFixture[str]
) -> None:
    """Through the real run_shardcert: a refused pool is exit 2 (setup), never a traceback or a bench
    result, and the store is never reset."""
    import harness.__main__ as cli

    _cli_env(monkeypatch)
    assert cli._run_shardcert(["--store-pool-size", str(POOL_SIZE_CLIFF)]) == 2
    assert reset_calls == []
    assert "refusing to run: STORE POOL AT/OVER" in capsys.readouterr().err


def test_engine_ladder_cli_refusal_is_a_setup_exit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import harness.__main__ as cli

    monkeypatch.setenv("MEFOR_STORE_BACKEND", "sqlserver")
    seen: list[object] = []

    async def refuse(**kwargs: object) -> None:
        seen.append(kwargs["force_store_pool_size"])
        raise StorePoolOverCliff("STORE POOL AT/OVER THE ADR 0062 CLIFF")

    monkeypatch.setattr("harness.load.shardcert_ladder.run_engine_ladder", refuse)
    argv = ["--rate-ladder", "24,28", "--sink-port", "9000", "--coord-dir", str(tmp_path)]
    assert cli._run_shardcert_engine_ladder(argv) == 2
    assert seen == [False]


def test_no_warning_below_the_cliff(capsys: pytest.CaptureFixture[str]) -> None:
    """The product default sits at the optimum; announce_store_pool already says so, so the check is
    silent there and only a forced run past the cliff prints."""
    assert shardcert.check_store_pool_size(shardcert.PRODUCT_STORE_POOL_SIZE, 4) is not None
    assert capsys.readouterr().err == ""
    shardcert.check_store_pool_size(POOL_SIZE_CLIFF, 4, force=True)
    assert "WARNING: STORE POOL AT/OVER" in capsys.readouterr().err


@pytest.mark.parametrize(("argv", "forced"), [([], False), (["--force-store-pool-size"], True)])
def test_cli_passes_the_force_flag(
    monkeypatch: pytest.MonkeyPatch, argv: list[str], forced: bool
) -> None:
    import harness.__main__ as cli

    _cli_env(monkeypatch)
    seen: list[object] = []

    async def capture(**kwargs: object) -> None:
        seen.append(kwargs["force_store_pool_size"])
        raise StorePoolOverCliff("stop here")

    monkeypatch.setattr(shardcert, "run_shardcert", capture)
    assert cli._run_shardcert(argv) == 2
    assert seen == [forced]
