# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Batch 20006 A: the batch_ab two-box engine half and remote-process runner (BACKLOG #5304, #5857).

* #5304, the failing-test half: the band-report tests engine PR 3109 added pass a ``timeout`` the
  pre-fix ``_run_remote_proc`` did not take, so they fail there on a TypeError, not on the defect.
  The two here call the runner with only the arguments its signature names, so each runs against
  the pre-fix source too and fails there on an assertion.
* #5857 item 1: S26-22, a layout any cell could not run is refused before any engine starts,
  through the same checks the engine's config loader and connscale-remote run; S26-23, a cell's
  engine is stopped when its start-up raises an OSError or the walk is cancelled.

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
from harness.load.coord import (
    BATCH_CELL_DONE,
    BATCH_CELL_READY,
    CoordMessageRefused,
    FileDropCoord,
)

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
    # The engines inherit it, and the layout check refuses a prefix the loader would.
    "MEFOR_CONNSCALE_NAME_PREFIX",
)


@pytest.fixture(autouse=True)
def _no_auth_env(monkeypatch: pytest.MonkeyPatch) -> None:
    # No sign-in limit or name prefix inherited from the calling shell can refuse the fleet first.
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
        (
            {"inbound_base": 65530},
            "count 8: the engine's connscale config refuses the shape: base_port 65530 + count 8 "
            "runs past port 65535",
        ),
        ({"api_base": 0}, "the API ports 0..0 run outside 1..65535"),
        # The loader bounds only the first sink port; connscale-remote refuses band 3's 65536.
        (
            {"sink_base": 65533},
            "count 8: connscale-remote refuses driver band 3: sink port 65536 runs past 65535",
        ),
        ({"api_base": 2603}, "API port 2603 falls in its inbound ports 2600..2607"),
        # Two driver bands of four: the sink ports 2604..2605 fall in the inbound block, which the
        # engine's config loader refuses.
        (
            {"sink_procs": 2, "sink_base": 2604},
            "inbound port block [2600, 2607] overlaps the sink port range [2604, 2605]",
        ),
        # The loader refuses ANY overlap of the whole inbound block and the whole sink range. A
        # check per driver band alone passes these, since no band's own sink port falls in its own
        # inbound sub-range, and then every engine fails at config load.
        (
            {"sink_base": 2595},
            "inbound port block [2600, 2607] overlaps the sink port range [2595, 2600]",
        ),
        (
            {"sink_procs": 2, "sink_base": 2607},
            "inbound port block [2600, 2607] overlaps the sink port range [2607, 2608]",
        ),
    ],
)
async def test_a_layout_a_cell_could_not_run_starts_no_engine(
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


async def test_only_ports_one_cell_binds_at_once_are_compared(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Counts [3, 8] at inbound 2600: API 2607 beside cell 0's 2600..2602, then 2608 beside cell 1's
    # 2600..2607, so no cell's own ports collide. A later cell may bind a port an earlier cell
    # released, so this runs.
    rec = _install_engine_fakes(monkeypatch)
    two_cells = _BATCH.replace("counts = [8]", "counts = [3, 8]")
    report, readies = await _engine_alone(two_cells, sink_procs=6, api_base=2607)
    assert report.ok, report.notes
    assert len(rec.started) == 2 and all("error" not in r for r in readies)
    # API 2605 then 2606: cell 1's own block 2600..2607 holds its API port.
    report, readies = await _engine_alone(two_cells, sink_procs=6, api_base=2605)
    said = "API port 2606 falls in its inbound ports 2600..2607"
    assert len(rec.started) == 2 and len(readies) == 2
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


def test_a_claim_mode_refusal_echoes_the_value_bounded_and_escaped() -> None:
    profile = load_connscale_profile_text(_BATCH)
    with pytest.raises(ConnScaleError) as caught:
        bb.iter_batch_cells(profile, claim_mode="x" * 10_000 + "\x1b[2J")
    said = str(caught.value)
    # Before, the whole 10,004-character value, escape sequence included, was echoed.
    assert len(said) < 300 and "(10004 characters)" in said, said
    with pytest.raises(ConnScaleError) as caught:
        bb.iter_batch_cells(profile, claim_mode="per\x1b[2Jlane")
    assert "\x1b" not in str(caught.value) and "per\\x1b[2Jlane" in str(caught.value)


#: A layout well clear of every collision, for a test that varies one other knob.
_FAR: dict[str, Any] = {
    "inbound_base": 2600,
    "api_base": 9000,
    "sink_base": 40000,
    "sink_host": "127.0.0.1",
}


def _cells(*counts: int) -> list[bb.BatchCell]:
    listed = ", ".join(str(n) for n in counts)
    profile = load_connscale_profile_text(_BATCH.replace("counts = [8]", f"counts = [{listed}]"))
    return bb.iter_batch_cells(profile, claim_mode="pooled")


@pytest.mark.parametrize(
    ("counts", "sink_procs", "said"),
    [
        # The engine's config loader caps the count at 5000 and its sink ports at 4096. A port
        # check alone passes both, and every engine of that count then fails at config load.
        ((5001,), 6, "count (MEFOR_CONNSCALE_COUNT) must be <= 5000, got 5001"),
        ((4097,), 4097, "sink ports (MEFOR_CONNSCALE_SINK_PORTS) must be <= 4096, got 4097"),
    ],
)
def test_the_layout_check_refuses_past_the_engine_loaders_caps(
    counts: tuple[int, ...], sink_procs: int, said: str
) -> None:
    with pytest.raises(ConnScaleError, match=r"refuses the shape: ") as caught:
        bb.check_engine_layout(_cells(*counts), sink_procs=sink_procs, **_FAR)
    assert said in str(caught.value)
    # CONTROL: one below each cap is admitted.
    bb.check_engine_layout(_cells(*(n - 1 for n in counts)), sink_procs=sink_procs - 1, **_FAR)


async def test_one_cell_past_a_cap_refuses_the_whole_matrix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Count 8 could run on its own; the 5001 cell beside it refuses the matrix before any starts.
    rec = _install_engine_fakes(monkeypatch)
    report, readies = await _engine_alone(
        _BATCH.replace("counts = [8]", "counts = [8, 5001]"), sink_procs=6
    )
    assert rec.built == []
    assert [c.count for c in report.cells] == [8, 5001]
    assert all(c.error and "must be <= 5000" in c.error for c in report.cells)
    assert len(readies) == 2 and all("must be <= 5000" in r.get("error", "") for r in readies)


def test_the_layout_check_admits_the_edges_of_the_port_space() -> None:
    cells = bb.iter_batch_cells(load_connscale_profile_text(_BATCH), claim_mode="per_lane")
    off_box = {"sink_host": "10.0.0.2"}
    bb.check_engine_layout(
        cells, sink_procs=1, inbound_base=1, api_base=65535, sink_base=65535, **off_box
    )
    bb.check_engine_layout(
        cells, sink_procs=6, inbound_base=65528, api_base=9, sink_base=1, sink_host="localhost"
    )
    # API blocks that end just below, or start just above, the inbound block 2600..2607.
    bb.check_engine_layout(cells, sink_procs=6, **{**_FAR, "api_base": 2599})
    bb.check_engine_layout(cells, sink_procs=6, **{**_FAR, "api_base": 2608})
    # ... and just below, or just above, a loopback sink range 40000..40005.
    bb.check_engine_layout(cells, sink_procs=6, **{**_FAR, "api_base": 39999})
    bb.check_engine_layout(cells, sink_procs=6, **{**_FAR, "api_base": 40006})
    bb.check_engine_layout(
        [], sink_procs=0, inbound_base=0, api_base=0, sink_base=0, sink_host="127.0.0.1"
    )


@pytest.mark.parametrize(
    "sink_host",
    # An empty host is the loader's 127.0.0.1; a dial to the unspecified address stays local.
    ["127.0.0.1", "localhost", "::1", "127.0.0.2", "", "  ", "0.0.0.0", "::"],
)
def test_an_api_port_in_a_loopback_sink_range_is_refused(sink_host: str) -> None:
    # The sinks bind on this box, so cell 0's API port 40002 would take band 2's sink port.
    with pytest.raises(ConnScaleError, match="API port 40002 falls in its sink ports 40000..40005"):
        bb.check_engine_layout(
            _cells(8), sink_procs=6, **{**_FAR, "api_base": 40002, "sink_host": sink_host}
        )
    # CONTROL: sinks on another box share no port with the engine's API.
    bb.check_engine_layout(
        _cells(8), sink_procs=6, **{**_FAR, "api_base": 40002, "sink_host": "10.0.0.2"}
    )


async def test_a_name_prefix_the_engine_loader_refuses_starts_no_engine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The engines inherit MEFOR_CONNSCALE_NAME_PREFIX from the calling shell; the loader refuses a
    # prefix outside [A-Za-z0-9_], so every engine would fail at config load.
    rec = _install_engine_fakes(monkeypatch)
    monkeypatch.setenv("MEFOR_CONNSCALE_NAME_PREFIX", "E-0")
    report, readies = await _engine_alone(sink_procs=6)
    assert rec.built == []
    assert all(c.error and "name prefix" in c.error for c in report.cells)
    assert readies and all("name prefix" in r.get("error", "") for r in readies)
    # CONTROL: a prefix the loader admits runs.
    monkeypatch.setenv("MEFOR_CONNSCALE_NAME_PREFIX", " E0 ")
    report, _ = await _engine_alone(sink_procs=6)
    assert report.ok, report.notes


def test_a_loader_refusal_echoes_an_inherited_value_bounded_and_escaped() -> None:
    hostile = "\x1b[2J" + "-" * 10_000
    with pytest.raises(ConnScaleError) as caught:
        bb.check_engine_layout(_cells(8), sink_procs=6, name_prefix=hostile, **_FAR)
    said = str(caught.value)
    assert "name prefix (MEFOR_CONNSCALE_NAME_PREFIX)" in said
    assert "\x1b" not in said and len(said) < 600 and "characters)" in said, said[:200]


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


@pytest.mark.parametrize(
    ("exc", "said"),
    [
        # The text resume_into_job raises when it cannot resume the started process.
        (
            OSError("node batch-x: could not resume the started process (status 0xc0000022)"),
            "OSError: node batch-x: could not resume the started process (status 0xc0000022)",
        ),
        (TimeoutError("health wait ran out"), "TimeoutError: health wait ran out"),
        # Cut short and made terminal-safe, so a long or hostile message cannot run on.
        (OSError("\x1b[2J" + "y" * 500), "OSError: \\x1b[2J" + "y" * 116 + "... (504 characters)"),
        # No text to keep: the type alone.
        (OSError(), "OSError"),
        (OSError(5), "OSError"),
    ],
)
async def test_a_one_argument_oserror_keeps_its_message(
    monkeypatch: pytest.MonkeyPatch, exc: OSError, said: str
) -> None:
    """Before, an OSError with no OS reason was named by its type alone, which dropped the one
    line saying why the engine did not start."""
    rec = _install_engine_fakes(monkeypatch)
    monkeypatch.setattr(bb, "_await_node_healthy", _raiser(exc))
    report, readies = await _engine_alone(sink_procs=6)
    assert [c.error for c in report.cells] == [f"engine did not start: {said}"]
    assert [r.get("error") for r in readies] == [f"engine did not start: {said}"]
    assert rec.started and rec.stopped == rec.started


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


async def test_a_failed_start_stops_its_engine_before_the_done_wait(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The cell's result is decided once its start fails, so its engine does not wait out the
    # driver's DONE, up to cell_timeout.
    rec = _install_engine_fakes(monkeypatch)
    monkeypatch.setattr(bb, "_await_node_healthy", _raiser(ConnScaleError("not healthy")))
    real_wait = FileDropCoord.await_message
    stopped_at_wait: list[list[str]] = []

    async def wait(self: FileDropCoord, name: str, **kwargs: Any) -> dict[str, Any]:
        if name == BATCH_CELL_DONE:
            stopped_at_wait.append(list(rec.stopped))
        return await real_wait(self, name, **kwargs)

    monkeypatch.setattr(FileDropCoord, "await_message", wait)
    report, readies = await _engine_alone(sink_procs=6)
    assert stopped_at_wait == [rec.started] and rec.stopped == rec.started
    assert readies and all("not healthy" in r.get("error", "") for r in readies)


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


async def test_a_refused_done_after_a_failed_start_stops_the_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A refused coord message stops the run with its own reason, as it does after a cell that
    started; before, the failed-start path noted its type and walked on to the next cell."""
    rec = _install_engine_fakes(monkeypatch)
    monkeypatch.setattr(bb, "_await_node_healthy", _raiser(ConnScaleError("not healthy")))
    refused = CoordMessageRefused("the DONE file is not a regular file")
    monkeypatch.setattr(FileDropCoord, "await_message", _raiser(refused))
    two_cells = load_connscale_profile_text(_BATCH.replace("counts = [8]", "counts = [3, 8]"))
    with tempfile.TemporaryDirectory() as tmp, pytest.raises(CoordMessageRefused):
        await bb.run_batch_engine(
            profile=two_cells,
            coord=FileDropCoord(tmp, run_id="batch_ab"),
            store_env={},
            sink_procs=6,
            cell_timeout=10.0,
        )
    assert len(rec.started) == 1 and rec.stopped == rec.started
