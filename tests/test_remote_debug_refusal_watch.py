# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A script the remote-debugging guard refused gets an audit row (vault BACKLOG #2742, item 3).

The owner's ruling (2026-10-13) fixes four things, and each has a test here: one audit action named
``remote_debug_refused``; ``serve`` only; one row for each pass, carrying a count; and no file name
in the row.

**How a refusal is driven.** An injection needs the operating system's leave to attach to a
process, which not every platform gives a test. So these tests call the guard's real hook function
with the interpreter's event, as ``tests/test_remote_debug_guard.py`` does. That moves the real
count the watch reads. The injection itself, through ``sys.remote_exec`` into a child, is that
file's subject. One test here does run a child interpreter: the state where an earlier audit hook
raises on the engine's probe event cannot be built in this process, because an audit hook cannot
be removed.
"""

from __future__ import annotations

import ast
import asyncio
import json
import logging
import os
import queue
import subprocess
import sys
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any, cast

import pytest

from messagefoundry import remotedebug
from messagefoundry.config.settings import EgressSettings
from messagefoundry.pipeline import Engine, remote_debug_watch
from messagefoundry.pipeline.remote_debug_watch import (
    AUDIT_ACTION,
    CHECK_INTERVAL_SECONDS,
    RemoteDebugRefusalWatch,
)
from messagefoundry.remotedebug import REMOTE_SCRIPT_EVENT, RemoteScriptRefused
from messagefoundry.store.base import AuditStore
from messagefoundry.store.store import MessageStore
from tests._ast_sites import call_sites, code_names, parse_source
from tests._refusal_log_capture import until

_REPO = Path(__file__).resolve().parents[1]
_ENGINE = _REPO / "messagefoundry"

#: A file name the injecting process might choose. Distinctive, so its absence from a row is a
#: finding and not an accident of the search.
PLANTED_NAME = "zqx-planted-script-name.py"
PLANTED_PATH = os.path.join("some", "directory", PLANTED_NAME)


@pytest.fixture
def refuse(monkeypatch: pytest.MonkeyPatch) -> Callable[..., None]:
    """Refuse one injected script, through the guard's real hook function.

    The count starts at zero and is put back afterwards, because it is module state that later
    tests in this process read. The report queue is private, so the reporter thread already
    running in this process cannot take a name a test here wants to read."""
    monkeypatch.setattr(remotedebug, "_reports", queue.SimpleQueue())
    monkeypatch.setattr(remotedebug, "_refused", 0)

    def _refuse(path: str = PLANTED_PATH, *, times: int = 1) -> None:
        for _ in range(times):
            with pytest.raises(RemoteScriptRefused):
                remotedebug._guard(REMOTE_SCRIPT_EVENT, (path,))

    return _refuse


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    opened = await MessageStore.open(tmp_path / "watch.db")
    try:
        yield opened
    finally:
        await opened.close()


async def _rows(store: MessageStore) -> list[dict[str, Any]]:
    """The watch's audit rows, oldest first, each with its detail parsed."""
    rows = await store.recent_audit_of([AUDIT_ACTION], limit=50)
    return [{**row, "detail": json.loads(row["detail"])} for row in reversed(rows)]


class _RefusingStore:
    """An audit store that refuses every write while ``down`` is set, and records the rest."""

    def __init__(self) -> None:
        self.down = False
        self.written: list[tuple[str, str | None, dict[str, Any]]] = []

    async def record_audit(
        self, action: str, *, actor: str | None = None, detail: str | None = None, **_kw: Any
    ) -> None:
        if self.down:
            raise RuntimeError("the audit log refuses writes")
        self.written.append((action, actor, json.loads(detail or "{}")))


def _on(store: object, **kw: Any) -> RemoteDebugRefusalWatch:
    return RemoteDebugRefusalWatch(cast(AuditStore, store), **kw)


# --- one row for each pass, with a count ---------------------------------------------------------


@pytest.mark.parametrize("refusals", [3, 1])
async def test_the_refusals_between_two_passes_make_one_row_with_their_count(
    store: MessageStore, refuse: Callable[..., None], refusals: int
) -> None:
    watch = _on(store)
    refuse(times=refusals)
    await watch.run_once()

    (row,) = await _rows(store)
    assert row["action"] == "remote_debug_refused"
    assert row["detail"] == {
        "count": refusals,
        "total": refusals,
        "process": None,
        "pid": os.getpid(),
    }
    # The engine wrote it, not a user, and no client address was in scope.
    assert row["actor"] == "system"


async def test_no_refusal_makes_no_row(store: MessageStore, refuse: Callable[..., None]) -> None:
    watch = _on(store)
    await watch.run_once()
    await watch.run_once()
    assert await _rows(store) == []
    # CONTROL: the same watch on the same store does write once something is refused, so the
    # empty reading above is not a watch that cannot write.
    refuse()
    await watch.run_once()
    assert len(await _rows(store)) == 1


async def test_two_passes_with_refusals_in_each_make_two_rows(
    store: MessageStore, refuse: Callable[..., None]
) -> None:
    watch = _on(store)
    refuse(times=2)
    await watch.run_once()
    refuse(times=5)
    await watch.run_once()
    await watch.run_once()  # nothing new: no third row

    assert [(row["detail"]["count"], row["detail"]["total"]) for row in await _rows(store)] == [
        (2, 2),
        (5, 7),
    ]


async def test_a_flood_between_two_passes_is_still_one_row(
    store: MessageStore, refuse: Callable[..., None]
) -> None:
    """The injecting process sets the rate. However many it tries, a pass adds one row."""
    watch = _on(store)
    refuse(times=500)
    await watch.run_once()
    (row,) = await _rows(store)
    assert row["detail"]["count"] == 500


async def test_the_first_pass_counts_from_the_start_of_the_process(
    store: MessageStore, refuse: Callable[..., None]
) -> None:
    """A refusal made before the watch exists is one made before the engine opened its store. A
    caller who can restart the engine aims for exactly that window."""
    refuse(times=4)
    watch = _on(store)
    await watch.run_once()
    (row,) = await _rows(store)
    assert (row["detail"]["count"], row["detail"]["total"]) == (4, 4)


async def test_the_row_names_the_engine_process(
    store: MessageStore, refuse: Callable[..., None]
) -> None:
    watch = _on(store, node="node:engine-b")
    refuse()
    await watch.run_once()
    (row,) = await _rows(store)
    assert row["detail"]["process"] == "node:engine-b"


# --- no file name --------------------------------------------------------------------------------


async def test_the_file_name_is_in_the_warning_and_not_in_the_row(
    store: MessageStore, refuse: Callable[..., None], caplog: pytest.LogCaptureFixture
) -> None:
    watch = _on(store)
    refuse(PLANTED_PATH)
    await watch.run_once()

    (raw,) = await store.recent_audit_of([AUDIT_ACTION], limit=5)
    assert PLANTED_NAME not in json.dumps(raw, default=str)
    assert "zqx" not in json.dumps(raw, default=str)
    # CONTROL: the hook did see that name, and the guard's WARNING line carries it. So the name
    # was there to leak, and the search above could have found it.
    queued = remotedebug._reports.get_nowait()
    assert queued == PLANTED_NAME
    with caplog.at_level(logging.WARNING, logger="messagefoundry.remotedebug"):
        remotedebug._report(queued)
    assert PLANTED_NAME in caplog.records[-1].getMessage()


async def test_a_refused_row_is_logged_without_a_file_name(
    refuse: Callable[..., None], caplog: pytest.LogCaptureFixture
) -> None:
    """The ERROR line for a row the store refused prints the row's detail, which holds no name."""
    refusing = _RefusingStore()
    refusing.down = True
    watch = _on(refusing)
    refuse(PLANTED_PATH)
    with caplog.at_level(logging.ERROR, logger=remote_debug_watch.__name__):
        await watch.run_once()
    (record,) = caplog.records
    assert record.levelno == logging.ERROR
    assert "remote_debug_refused audit row failed" in record.getMessage()
    assert PLANTED_NAME not in record.getMessage() and '"count": 1' in record.getMessage()


# --- a row the store refuses is owed -------------------------------------------------------------


async def test_a_row_the_store_refuses_is_written_by_a_later_pass_with_the_larger_count(
    refuse: Callable[..., None],
) -> None:
    refusing = _RefusingStore()
    watch = _on(refusing)
    refusing.down = True
    refuse(times=2)
    await watch.run_once()
    refuse(times=3)
    await watch.run_once()
    assert refusing.written == []

    refusing.down = False
    await watch.run_once()
    await watch.run_once()  # paid: nothing more is owed
    ((action, actor, detail),) = refusing.written
    assert (action, actor) == ("remote_debug_refused", "system")
    assert (detail["count"], detail["total"]) == (5, 5)


async def test_two_passes_at_once_write_one_row(refuse: Callable[..., None]) -> None:
    """The mark moves after the write. Without a turn each, both passes would read the same
    refusals as unreported and each write a row for them."""

    class _Slow(_RefusingStore):
        async def record_audit(self, action: str, **kw: Any) -> None:
            await asyncio.sleep(0.01)
            await super().record_audit(action, **kw)

    slow = _Slow()
    watch = _on(slow)
    refuse(times=3)
    await asyncio.gather(watch.run_once(), watch.run_once())
    assert [(d["count"], d["total"]) for _a, _actor, d in slow.written] == [(3, 3)]


async def test_a_count_that_was_put_back_is_measured_from_there(
    refuse: Callable[..., None], monkeypatch: pytest.MonkeyPatch
) -> None:
    refusing = _RefusingStore()
    watch = _on(refusing)
    refuse(times=6)
    await watch.run_once()
    monkeypatch.setattr(remotedebug, "_refused", 0)
    await watch.run_once()
    refuse(times=2)
    await watch.run_once()
    assert [(d["count"], d["total"]) for _a, _actor, d in refusing.written] == [(6, 6), (2, 2)]


# --- the loop ------------------------------------------------------------------------------------


async def test_the_loop_passes_at_once_and_again_as_it_stops(
    refuse: Callable[..., None],
) -> None:
    """An hour-long interval, so only the first pass and the last one can have run."""
    refusing = _RefusingStore()
    watch = _on(refusing, interval_seconds=3600.0)
    refuse(times=2)
    watch.start()
    try:
        await until(lambda: len(refusing.written) == 1, "the first pass's row")
        refuse(times=3)  # in the last interval: no timed pass will come for it
    finally:
        await watch.stop()
    assert [(d["count"], d["total"]) for _a, _actor, d in refusing.written] == [(2, 2), (3, 5)]
    await watch.stop()  # idempotent


async def test_a_pass_that_fails_does_not_end_the_loop(
    refuse: Callable[..., None], caplog: pytest.LogCaptureFixture
) -> None:
    refusing = _RefusingStore()
    readings = iter([RuntimeError("no reading")])

    def read() -> int:
        fault = next(readings, None)
        if fault is not None:
            raise fault
        return 1

    watch = _on(refusing, read=read, interval_seconds=0.01)
    with caplog.at_level(logging.ERROR, logger=remote_debug_watch.__name__):
        watch.start()
        try:
            await until(lambda: bool(refusing.written), "the row after the failed pass")
        finally:
            await watch.stop()
    assert any("check failed" in record.getMessage() for record in caplog.records)
    assert len(refusing.written) == 1


async def test_a_last_pass_that_hangs_is_cancelled(
    refuse: Callable[..., None], monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Hung(_RefusingStore):
        async def record_audit(self, action: str, **_kw: Any) -> None:
            await asyncio.Event().wait()

    monkeypatch.setattr(remote_debug_watch, "_STOP_SECONDS", 0.05)
    watch = _on(_Hung(), interval_seconds=3600.0)
    refuse()
    watch.start()
    await asyncio.sleep(0)
    task = watch._task
    assert task is not None
    await watch.stop()
    assert task.cancelled()


def test_the_interval_is_the_one_the_documents_state() -> None:
    """One row a pass, so the interval is the bound on rows. ``docs/SECURITY-LOOSENING.md`` gives
    it as 30 seconds, and a shorter one would let the injecting process add rows faster."""
    assert CHECK_INTERVAL_SECONDS == 30.0


# --- the engine runs it, and only serve builds an engine -----------------------------------------


async def test_the_engine_writes_the_row_on_its_own_store(
    tmp_path: Path, refuse: Callable[..., None], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Engine, "instance_identity", property(lambda _self: "shard:a"))
    opened = await MessageStore.open(tmp_path / "engine.db")
    engine = Engine(opened, egress_settings=EgressSettings(deny_by_default=False))
    await engine.start()
    try:
        watch = engine._remote_debug_watch
        assert watch is not None and watch._task is not None
        assert watch._store is opened and watch._node == "shard:a"
        refuse(times=3)
        await watch.run_once()
        refuse(times=2)  # left for the pass the engine's stop makes
    finally:
        await engine.stop()  # which closes the store, so the rows are read from a second open
    assert engine._remote_debug_watch is None
    reopened = await MessageStore.open(tmp_path / "engine.db")
    try:
        details = [row["detail"] for row in await _rows(reopened)]
    finally:
        await reopened.close()
    assert [(d["count"], d["total"], d["process"]) for d in details] == [
        (3, 3, "shard:a"),
        (2, 5, "shard:a"),
    ]


def _functions_naming(source: str, name: str) -> set[str]:
    """The top-level functions of ``source`` whose code spells ``name``, imports included."""
    found = set()
    for node in parse_source(source).body:
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        imported = {
            alias.name
            for sub in ast.walk(node)
            if isinstance(sub, ast.Import | ast.ImportFrom)
            for alias in sub.names
        }
        if name in code_names(node) | imported:
            found.add(node.name)
    return found


def _construction_sites(name: str) -> list[str]:
    """Each file of the engine package that calls ``name``, as a posix path under the package."""
    sites = []
    for path in sorted(_ENGINE.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        if name in text and call_sites(parse_source(text), name):
            sites.append(path.relative_to(_ENGINE).as_posix())
    return sites


def test_only_serve_builds_what_runs_the_watch() -> None:
    """A census, from the watch back to the command line: the watch is built in one place, the
    engine; the engine is built in one place, the managed app; and of the command line's
    functions only ``serve`` names the managed app. So ``supervise``, ``rotate-key``, ``backup``
    and every other command start no watch."""
    assert _construction_sites("RemoteDebugRefusalWatch") == ["pipeline/engine.py"]
    # `Engine(...)` in the package. `Engine.create(...)` is a classmethod on the engine itself,
    # called by tests and embedders, never by a command.
    assert _construction_sites("Engine") == ["api/app.py"]
    assert _construction_sites("create_managed_app") == ["__main__.py"]

    command_line = (_ENGINE / "__main__.py").read_text(encoding="utf-8")
    assert _functions_naming(command_line, "create_managed_app") == {"_serve"}
    for reach in ("Engine", "RemoteDebugRefusalWatch", "remote_debug_watch"):
        assert _functions_naming(command_line, reach) == set(), reach
    # CONTROL: the probe does see a name a command function uses, so the empty sets above are
    # not a probe that finds nothing.
    assert "_supervise" in _functions_naming(command_line, "install_remote_debug_guard")


# --- the state where the guard reads as missing --------------------------------------------------

_SECOND_CAUSE = """\
import asyncio, json, sys

from messagefoundry import remotedebug
from messagefoundry.pipeline.remote_debug_watch import RemoteDebugRefusalWatch

mode, out = sys.argv[1], sys.argv[2]


def earlier(event, args):
    if mode == "probe" and event == remotedebug._PROBE_EVENT:
        raise ValueError("an event this hook does not know")
    if mode == "refuses" and event == "sys.addaudithook":
        raise RuntimeError("this hook refuses every new one")


sys.addaudithook(earlier)
remotedebug.install_remote_debug_guard()
sys.unraisablehook = lambda unraisable: None
refused = 0
for _ in range(3):
    try:
        sys.audit(remotedebug.REMOTE_SCRIPT_EVENT, "C:/somewhere/zqx-planted-script-name.py")
    except remotedebug.RemoteScriptRefused:
        refused += 1


class Store:
    rows = []

    async def record_audit(self, action, *, actor=None, detail=None):
        self.rows.append(json.loads(detail))


asyncio.run(RemoteDebugRefusalWatch(Store()).run_once())
posture = remotedebug.remote_debug_posture()
with open(out, "w", encoding="utf-8") as fh:
    json.dump(
        {
            "enabled": posture.interpreter_enabled,
            "guard_installed": posture.guard_installed,
            "refused": refused,
            "rows": [[row["count"], row["total"]] for row in Store.rows],
        },
        fh,
    )
"""


def _second_cause(tmp_path: Path, mode: str) -> dict[str, Any]:
    script = tmp_path / "second_cause.py"
    script.write_text(_SECOND_CAUSE, encoding="utf-8")
    out = tmp_path / f"{mode}.json"
    env = dict(os.environ)
    env.pop("PYTHON_DISABLE_REMOTE_DEBUG", None)
    env["PYTHONPATH"] = str(_REPO)
    try:
        proc = subprocess.run(
            [sys.executable, str(script), mode, str(out)],
            env=env,
            capture_output=True,
            text=True,
            timeout=50,  # under the suite's per-test watchdog, so a hung child is reported here
        )
    except subprocess.TimeoutExpired as exc:
        pytest.fail(f"the child did not finish: {exc.stderr!r}")
    assert proc.returncode == 0 and out.exists(), proc.stderr[-2000:]
    reading: dict[str, Any] = json.loads(out.read_text(encoding="utf-8"))
    if reading["enabled"] is not True:
        # An interpreter built without the interface: the guard installs nothing there.
        pytest.skip("the child interpreter does not accept injected scripts")
    return reading


def test_a_guard_that_reads_as_missing_but_refuses_still_gets_its_row(tmp_path: Path) -> None:
    """An earlier audit hook raises on the engine's probe event. The posture then reads the guard
    as missing and the guard starts no reporter, so no WARNING is written. The hook is in place
    all the same: it refuses and counts, and the watch reads the count."""
    reading = _second_cause(tmp_path, "probe")
    assert reading["guard_installed"] is False
    assert reading["refused"] == 3
    assert reading["rows"] == [[3, 3]]


def test_a_guard_that_is_missing_refuses_nothing_and_gets_no_row(tmp_path: Path) -> None:
    """CONTROL for the test above, and the limit of this watch: where an earlier hook refused the
    engine's, nothing is refused, nothing is counted and no row is written."""
    reading = _second_cause(tmp_path, "refuses")
    assert reading["guard_installed"] is False
    assert reading["refused"] == 0
    assert reading["rows"] == []
