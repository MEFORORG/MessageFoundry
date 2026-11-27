# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Batch 20006 A: the batch_ab two-box engine half and remote-process runner (BACKLOG #5304, #5857).

* #5304, the failing-test half: the band-report tests engine PR 3109 added pass a ``timeout`` the
  pre-fix ``_run_remote_proc`` did not take, so they fail there on a TypeError, not on the defect.
  The two here call the runner with only the arguments its signature names, so each runs against
  the pre-fix source too and fails there on an assertion.
* #5857 item 1: S26-22, a layout no cell could run is refused before any engine starts; S26-23,
  a cell's engine is stopped when its start-up raises an OSError or the walk is cancelled.

Every engine collaborator is faked; no engine or connscale-remote process starts, and the only
children spawned are one-line ``python -c`` scripts.
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import sys
import tempfile
import types
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

import harness.load.connscale.batchbox as bb
from harness.load.connscale.profile import load_connscale_profile_text
from harness.load.connscale.runner import ConnScaleError
from harness.load.coord import BATCH_CELL_DONE, BATCH_CELL_READY, FileDropCoord

_BATCH = """\
[connscale]
name = "batch_b20006"
claim_modes = ["pooled"]
fuse_modes = [false]
batch_modes = [false]
trials = 1
counts = [8]
sweep_mode = "fixed_aggregate"
aggregate_rate = 24.0
hold_seconds = 0.1
drain_timeout_s = 1.0
base_port = 2600
"""

_AUTH_ENV = (
    "MEFOR_AUTH_MAX_SESSIONS_PER_USER",
    "MEFOR_AUTH_LOGIN_RATE_LIMIT_PER_IP",
    "MEFOR_AUTH_LOGIN_RATE_LIMIT_GLOBAL",
    "MEFOR_AUTH_LOGIN_RATE_LIMIT_ENABLED",
    "MEFOR_AUTH_LOGIN_RATE_LIMIT_WINDOW_SECONDS",
)


@pytest.fixture(autouse=True)
def _no_auth_env(monkeypatch: pytest.MonkeyPatch) -> None:
    # No sign-in limit inherited from the calling shell can refuse the fleet first.
    for name in _AUTH_ENV:
        monkeypatch.delenv(name, raising=False)


# --- BACKLOG #5304: the runner, called the way either source accepts -------------------------------


async def _run_remote(argv: list[str], report: Path, cwd: Path) -> dict[str, Any] | ConnScaleError:
    """``_run_remote_proc`` with a bound only where its signature takes one, so the same test runs
    on the pre-fix source. A ConnScaleError is returned, not raised, so a test fails on its
    assertion whichever source it runs on."""
    kwargs: dict[str, Any] = {}
    if "timeout" in inspect.signature(bb._run_remote_proc).parameters:
        kwargs["timeout"] = 60.0
    try:
        return await bb._run_remote_proc(argv, report, cwd, **kwargs)
    except ConnScaleError as exc:
        return exc


async def test_a_child_that_writes_no_report_never_hands_back_an_earlier_one(
    tmp_path: Path,
) -> None:
    report = tmp_path / "cell.p0.json"
    report.write_text('{"sent": 99, "stale": true}', encoding="utf-8")
    child = "import sys; sys.stderr.write('connscale-remote setup failed: refused'); sys.exit(2)"
    got = await _run_remote([sys.executable, "-c", child], report, tmp_path)
    # Pre-fix, this returned the stale {"sent": 99, "stale": True}.
    assert isinstance(got, ConnScaleError), got
    assert "exited 2 and wrote no report" in str(got) and "refused" in str(got)
    assert not report.exists()
    # CONTROL: with the stale report planted again, a child that writes its own is read.
    report.write_text('{"sent": 99, "stale": true}', encoding="utf-8")
    writer = f"open({str(report)!r}, 'w').write('{{\"sent\": 3}}')"
    assert await _run_remote([sys.executable, "-c", writer], report, tmp_path) == {"sent": 3}


async def test_a_report_on_disk_does_not_excuse_an_exit_it_does_not_record(
    tmp_path: Path,
) -> None:
    report = tmp_path / "written.json"

    def child(payload: dict[str, Any]) -> list[str]:
        script = (
            f"import json, sys; json.dump({payload!r}, open({str(report)!r}, 'w')); "
            "sys.stderr.write('Traceback: the reason'); sys.exit(1)"
        )
        return [sys.executable, "-c", script]

    got = await _run_remote(child({"sent": 3}), report, tmp_path)
    # Pre-fix, a report on disk was read whatever the exit code.
    assert isinstance(got, ConnScaleError), got
    assert "exited 1, but its report records" in str(got) and "the reason" in str(got)
    # CONTROL: a FAIL verdict the report records (exit 1, "exit_code": 1) is read.
    verdict = {"sent": 3, "exit_code": 1}
    assert await _run_remote(child(verdict), report, tmp_path) == verdict


# --- BACKLOG #5857 item 1: the engine half ---------------------------------------------------------


def _install_engine_fakes(monkeypatch: pytest.MonkeyPatch) -> types.SimpleNamespace:
    rec = types.SimpleNamespace(built=[], started=[], stopped=[])

    class FakeNode:
        alive = False
        pid = 4242

        def __init__(
            self, node_id: str, api_port: int, *, env: Mapping[str, str], config_dir: str, cwd: Any
        ) -> None:
            self.node_id = node_id
            rec.built.append(node_id)

        async def start(self) -> None:
            rec.started.append(self.node_id)

        async def stop(self) -> None:
            rec.stopped.append(self.node_id)

    async def fine(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(bb, "EngineNode", FakeNode)
    monkeypatch.setattr(bb, "_await_node_healthy", fine)
    monkeypatch.setattr(bb, "_await_port", fine)
    rec.node_cls = FakeNode
    return rec


def _raiser(exc: BaseException) -> Any:
    async def _raise(*_args: object, **_kwargs: object) -> None:
        raise exc

    return _raise


async def _engine_alone(
    profile_text: str = _BATCH, **kwargs: Any
) -> tuple[Any, list[dict[str, Any]]]:
    """The engine half beside a stand-in driver that posts DONE for each READY at once. The
    stand-in is cancelled when the engine half raises, so it never outlives the coord directory."""
    profile = load_connscale_profile_text(profile_text)
    readies: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory() as tmp:
        coord = FileDropCoord(tmp, run_id="batch_ab")

        async def stub_driver() -> None:
            for cell in bb.iter_batch_cells(profile, claim_mode="pooled"):
                cc = coord.for_run(f"batch_ab.{cell.cell_id}")
                readies.append(
                    await cc.await_message(BATCH_CELL_READY, timeout=10.0, interval=0.02)
                )
                cc.post(BATCH_CELL_DONE, {"cell_id": cell.cell_id})

        driver = asyncio.ensure_future(stub_driver())
        try:
            report = await bb.run_batch_engine(
                profile=profile, coord=coord, store_env={}, cell_timeout=10.0, **kwargs
            )
            await driver
        finally:
            driver.cancel()
            await asyncio.gather(driver, return_exceptions=True)
    return report, readies


@pytest.mark.parametrize(
    ("layout", "said"),
    [
        ({"sink_procs": 0}, "sink_procs must be >= 1, got 0"),
        # The CLI's --inbound-base is not bounded by the profile's own base_port check.
        ({"inbound_base": 65530}, "the inbound ports 65530..65537 run outside 1..65535"),
        ({"api_base": 0}, "the API ports 0..0 run outside 1..65535"),
        ({"sink_base": 65533}, "the sink ports 65533..65538 run outside 1..65535"),
        ({"api_base": 2603}, "the API ports 2603..2603 overlap the inbound ports 2600..2607"),
    ],
)
async def test_a_layout_no_cell_could_run_starts_no_engine(
    monkeypatch: pytest.MonkeyPatch, layout: dict[str, Any], said: str
) -> None:
    """S26-22: each of these used to start the cell's engine and fail it later, if at all. Now no
    engine starts, and every cell posts an error READY so the driver box skips it."""
    rec = _install_engine_fakes(monkeypatch)
    report, readies = await _engine_alone(**{"sink_procs": 6, **layout})

    assert rec.built == rec.started == []
    assert not report.ok
    assert report.cells and all(c.error and said in c.error for c in report.cells)
    assert readies and all(said in r.get("error", "") for r in readies), readies
    assert any(n.startswith("ENGINE LAYOUT REFUSED, NO CELL RAN") for n in report.notes)


async def test_an_api_port_inside_a_later_cells_inbound_block_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Cell 0 (3 connections) binds 2600..2602 beside API 2605; cell 1 (8) binds 2600..2607, which
    # holds the API port cell 0 just released.
    rec = _install_engine_fakes(monkeypatch)
    report, readies = await _engine_alone(
        _BATCH.replace("counts = [8]", "counts = [3, 8]"), sink_procs=6, api_base=2605
    )
    assert rec.started == [] and len(readies) == 2
    said = "the API ports 2605..2606 overlap the inbound ports 2600..2607"
    assert all(c.error and said in c.error for c in report.cells)


async def test_a_claim_mode_the_engine_does_not_read_builds_no_cell(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """S26-22: the cell ids name the coord files, so a claim mode is refused before any is built,
    by both halves, the way a profile with a sandbox arm is."""
    rec = _install_engine_fakes(monkeypatch)
    profile = load_connscale_profile_text(_BATCH)
    with pytest.raises(ConnScaleError, match="claim mode '../fifo' is not one of"):
        bb.iter_batch_cells(profile, claim_mode="../fifo")
    with tempfile.TemporaryDirectory() as tmp:
        with pytest.raises(ConnScaleError, match="claim mode 'fifo' is not one of"):
            await bb.run_batch_engine(
                profile=profile,
                claim_mode="fifo",
                coord=FileDropCoord(tmp, run_id="batch_ab"),
                store_env={},
                cell_timeout=1.0,
            )
        assert list(Path(tmp).iterdir()) == []
    assert rec.built == []


def test_the_layout_check_admits_the_edges_of_the_port_space() -> None:
    cells = bb.iter_batch_cells(load_connscale_profile_text(_BATCH), claim_mode="per_lane")
    bb.check_engine_layout(cells, sink_procs=1, inbound_base=1, api_base=65535, sink_base=65535)
    bb.check_engine_layout(cells, sink_procs=6, inbound_base=65528, api_base=9, sink_base=1)
    # API blocks that end just below, or start just above, the inbound block 2600..2607.
    bb.check_engine_layout(cells, sink_procs=6, inbound_base=2600, api_base=2599, sink_base=40000)
    bb.check_engine_layout(cells, sink_procs=6, inbound_base=2600, api_base=2608, sink_base=40000)
    bb.check_engine_layout([], sink_procs=0, inbound_base=0, api_base=0, sink_base=0)


async def test_the_default_layout_still_runs(monkeypatch: pytest.MonkeyPatch) -> None:
    rec = _install_engine_fakes(monkeypatch)
    report, readies = await _engine_alone(sink_procs=6)
    assert report.ok, report.notes
    assert len(rec.started) == 1 and rec.stopped == rec.started
    assert readies and all("error" not in r for r in readies)


async def test_an_engine_whose_start_raises_oserror_is_stopped_and_the_cell_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """S26-23: an OSError after the engine started used to end the walk with the engine running,
    and the driver box waiting on a READY that never came. The OS reason is kept; the path the
    error names is not."""
    rec = _install_engine_fakes(monkeypatch)
    monkeypatch.setattr(
        bb, "_await_node_healthy", _raiser(OSError(13, "Permission denied", "C:/nowhere/cert.pem"))
    )
    report: Any = None
    readies: list[dict[str, Any]] = []
    with contextlib.suppress(OSError):  # main let it escape
        report, readies = await _engine_alone(sink_procs=6)
    assert rec.started and rec.stopped == rec.started
    assert report is not None and not report.ok
    said = "engine did not start: PermissionError: Permission denied"
    assert all(c.error == said for c in report.cells), report.cells
    assert readies and all(r.get("error") == said for r in readies)
    assert "nowhere" not in repr(report.to_json_dict())


async def test_an_engine_that_cannot_be_built_fails_the_cell(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # EngineNode mints the run's TLS pair and opens its log file when it is built.
    rec = _install_engine_fakes(monkeypatch)

    def no_room(*_args: object, **_kwargs: object) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(rec.node_cls, "__init__", no_room)
    report, readies = await _engine_alone(sink_procs=6)
    said = "engine did not start: OSError: No space left on device"
    assert [c.error for c in report.cells] == [said]
    assert [r.get("error") for r in readies] == [said]
    assert rec.started == rec.stopped == []


async def test_a_failed_error_ready_post_still_stops_the_engine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rec = _install_engine_fakes(monkeypatch)
    monkeypatch.setattr(bb, "_await_node_healthy", _raiser(ConnScaleError("not healthy")))

    def share_gone(self: FileDropCoord, name: str, payload: Mapping[str, Any]) -> None:
        raise OSError("the coord share went away")

    monkeypatch.setattr(FileDropCoord, "post", share_gone)
    with tempfile.TemporaryDirectory() as tmp, pytest.raises(OSError, match="share went away"):
        await bb.run_batch_engine(
            profile=load_connscale_profile_text(_BATCH),
            coord=FileDropCoord(tmp, run_id="batch_ab"),
            store_env={},
            sink_procs=6,
            cell_timeout=10.0,
        )
    assert rec.started and rec.stopped == rec.started


async def _walk_is_cancelled() -> None:
    with tempfile.TemporaryDirectory() as tmp, pytest.raises(asyncio.CancelledError):
        await bb.run_batch_engine(
            profile=load_connscale_profile_text(_BATCH),
            coord=FileDropCoord(tmp, run_id="batch_ab"),
            store_env={},
            sink_procs=6,
            cell_timeout=10.0,
        )


@pytest.mark.parametrize("seam", ["_await_node_healthy", "_await_port"])
async def test_a_cancelled_start_up_stops_the_cells_engine(
    monkeypatch: pytest.MonkeyPatch, seam: str
) -> None:
    """S26-23: a cancellation during the health or port wait still ends the walk, and now takes
    the engine the cell started with it."""
    rec = _install_engine_fakes(monkeypatch)
    monkeypatch.setattr(bb, seam, _raiser(asyncio.CancelledError()))
    await _walk_is_cancelled()
    assert rec.started and rec.stopped == rec.started


async def test_a_cancelled_done_wait_after_a_failed_start_stops_the_engine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rec = _install_engine_fakes(monkeypatch)
    monkeypatch.setattr(bb, "_await_node_healthy", _raiser(ConnScaleError("not healthy")))
    monkeypatch.setattr(FileDropCoord, "await_message", _raiser(asyncio.CancelledError()))
    await _walk_is_cancelled()
    assert rec.started and rec.stopped == rec.started
