# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""WP-L3-19: process-level last-resort error handling (ASVS 16.5.4).

Verifies the asyncio loop handler + sys.excepthook + threading.excepthook route an otherwise-unhandled
exception through ``safe_exc`` (PHI-redacted, type-preserving) → the log, and that a framed listener
(MLLP) survives a handler that raises — the error is logged redacted, the connection drops, the server
stays up.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.last_resort import (
    _excepthook,
    _thread_excepthook,
    install_excepthook,
    install_loop_exception_handler,
    install_thread_excepthook,
)
from messagefoundry.transports.mllp import MLLPSource, frame

# A PHI-bearing HL7 fragment to embed in raised exceptions; must never reach a log line.
PHI = "PID|1||100^^^H^MR||DOE^JANE"


async def test_loop_handler_logs_unhandled_exception_redacted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    loop = asyncio.get_running_loop()
    original = loop.get_exception_handler()
    install_loop_exception_handler()
    try:

        def boom() -> None:
            raise ValueError(PHI)  # a callback that raises → the loop calls our exception handler

        with caplog.at_level(logging.ERROR):
            loop.call_soon(boom)
            await asyncio.sleep(0.05)  # let the callback run and the handler fire
    finally:
        loop.set_exception_handler(original)
    logged = " ".join(r.getMessage() for r in caplog.records)
    assert "last-resort" in logged and "ValueError" in logged  # type kept
    assert "DOE" not in logged and "JANE" not in logged  # PHI redacted by safe_exc


def test_excepthook_redacts_and_passes_keyboard_interrupt(
    caplog: pytest.LogCaptureFixture,
) -> None:
    err = RuntimeError(PHI)
    with caplog.at_level(logging.CRITICAL):
        _excepthook(type(err), err, err.__traceback__)
    logged = " ".join(r.getMessage() for r in caplog.records)
    assert "uncaught exception" in logged and "RuntimeError" in logged
    assert "DOE" not in logged  # PHI redacted

    # KeyboardInterrupt delegates to the default hook (clean Ctrl-C), not our redacted-error path.
    caplog.clear()
    ki = KeyboardInterrupt()
    with caplog.at_level(logging.CRITICAL):
        _excepthook(type(ki), ki, None)
    assert not caplog.records  # nothing logged as an error for a clean interrupt


def test_install_excepthook_sets_sys_hook() -> None:
    import sys

    original = sys.excepthook
    try:
        install_excepthook()
        assert sys.excepthook is _excepthook
    finally:
        sys.excepthook = original


# --- threading.excepthook (BACKLOG #1055) -------------------------------------
# sys.excepthook covers the MAIN thread only; an exception escaping any other thread's run() goes to
# threading.excepthook and nowhere else. The engine's concrete case is the sandbox session's raw
# stdout-reader daemon, whose except clause catches only OSError by design.


@pytest.fixture
def _restore_thread_excepthook() -> Iterator[None]:
    original = threading.excepthook
    try:
        yield
    finally:
        threading.excepthook = original


def test_thread_excepthook_redacts_an_exception_escaping_a_real_thread(
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
    _restore_thread_excepthook: None,
) -> None:
    """The end-to-end shape: a live thread raises, the interpreter dispatches to the hook."""
    install_thread_excepthook()

    def boom() -> None:
        raise ValueError(PHI)  # a non-OSError escaping run() — what the reader loop does not catch

    with caplog.at_level(logging.CRITICAL):
        worker = threading.Thread(target=boom, name="mefor-sandbox-reader")
        worker.start()
        worker.join(timeout=5)
    assert not worker.is_alive()

    logged = " ".join(r.getMessage() for r in caplog.records)
    assert "uncaught exception in thread" in logged
    assert "mefor-sandbox-reader" in logged  # which thread died stays diagnosable
    assert "ValueError" in logged  # ...and so does the type
    assert "DOE" not in logged and "JANE" not in logged  # PHI redacted by safe_exc

    # The stdlib default would have printed a raw traceback quoting the exception's argument straight
    # to stderr, bypassing the handler filter chain entirely. Nothing reaches stderr now.
    captured = capsys.readouterr()
    assert "DOE" not in captured.err and "JANE" not in captured.err
    assert "Traceback" not in captured.err


def test_thread_excepthook_ignores_system_exit(caplog: pytest.LogCaptureFixture) -> None:
    # Parity with the stdlib default, which silently ignores SystemExit: a thread calling sys.exit()
    # is a clean exit, and reporting it as a CRITICAL last-resort error would be a false alarm.
    exc = SystemExit(0)
    with caplog.at_level(logging.CRITICAL):
        _thread_excepthook(
            threading.ExceptHookArgs((SystemExit, exc, None, threading.current_thread()))
        )
    assert not caplog.records


def test_thread_excepthook_tolerates_a_missing_exc_value(caplog: pytest.LogCaptureFixture) -> None:
    # threading.ExceptHookArgs types exc_value as optional; the hook must not raise inside the hook.
    with caplog.at_level(logging.CRITICAL):
        _thread_excepthook(threading.ExceptHookArgs((ValueError, None, None, None)))
    assert not caplog.records


def test_install_thread_excepthook_sets_hook(_restore_thread_excepthook: None) -> None:
    install_thread_excepthook()
    assert threading.excepthook is _thread_excepthook


async def test_mllp_handler_exception_is_caught_and_redacted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def boom(raw: bytes) -> str:
        raise ValueError(PHI)  # an unexpected handler failure carrying PHI

    source = MLLPSource(Source(type=ConnectorType.MLLP, settings={"host": "127.0.0.1", "port": 0}))
    await source.start(boom)
    try:
        with caplog.at_level(logging.ERROR):
            reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
            writer.write(frame("MSH|^~\\&|s|f|r|rf|20260616||ADT^A01|1|P|2.5.1\rPID|1||x"))
            await writer.drain()
            # the listener catches the handler error, logs it, answers AE, then closes (BACKLOG
            # #1619; it used to close with no reply). The NAK text is fixed, so no PHI.
            nak = await asyncio.wait_for(reader.readuntil(b"\x1c"), timeout=5)
            assert b"MSA|AE|1|" in nak
            assert b"DOE" not in nak and b"JANE" not in nak
            writer.close()
            await writer.wait_closed()
        # the server survived — it still accepts a fresh connection
        r2, w2 = await asyncio.open_connection("127.0.0.1", source.sockport)
        w2.close()
        await w2.wait_closed()
    finally:
        await source.stop()
    logged = " ".join(r.getMessage() for r in caplog.records)
    assert "failed unexpectedly" in logged and "ValueError" in logged  # caught + type kept
    assert "DOE" not in logged and "JANE" not in logged  # PHI redacted


# --- every loop outside `serve` carries the handler (BACKLOG #1789) ---------------------------------

_UNAWAITED_TASK_DRIVER = """\
import asyncio, gc, json, logging, sys, types

records = []


class _Collect(logging.Handler):
    def emit(self, record):
        records.append({"level": record.levelname, "message": record.getMessage()})


logging.getLogger("messagefoundry.last_resort").addHandler(_Collect())

import messagefoundry.pipeline.dr_backup as dr


async def _fake_restore_verify(archive, *, store_settings, full):
    async def _fault():
        raise RuntimeError(PHI)

    task = asyncio.get_running_loop().create_task(_fault())
    for _ in range(3):
        await asyncio.sleep(0)  # let the task run and fail
    del task  # nothing awaits it and nothing holds it now
    gc.collect()  # collected WHILE the loop is alive, so the loop's handler is the one asked
    return types.SimpleNamespace(
        status="PASS", integrity_ok=True, row_counts={}, manifest_counts={},
        decrypted_cells=0, reason="", ok=True,
    )


dr.run_restore_verify = _fake_restore_verify
import messagefoundry.__main__ as m

rc = m.main(["restore-verify", sys.argv[1]])
with open(sys.argv[2], "w", encoding="utf-8") as fh:
    json.dump({"rc": rc, "records": records}, fh)
"""


def test_an_unawaited_task_exception_under_a_non_serve_subcommand_reaches_last_resort(
    tmp_path: Path,
) -> None:
    """The PROPERTY, not the call: a task exception nothing awaits, in a loop a non-serve CLI
    subcommand started, reaches the ``messagefoundry.last_resort`` logger redacted (BACKLOG #1789).

    A child interpreter runs the real ``restore-verify`` dispatch through ``main``. Only the library
    coroutine it awaits is replaced, with one that fails a task, drops the only reference and runs
    ``gc.collect()`` while the loop is still alive. That is when asyncio asks the loop's exception
    handler. Asserting that ``run_guarded`` was called would pass on a wrapper that installs nothing.

    RED when: the ``restore-verify`` site reverts to a bare ``asyncio.run``, or ``run_guarded``
    stops setting the handler. The stdlib default then logs to the ``asyncio`` logger instead, with
    the raw message in its traceback, and nothing reaches this logger. The other sites are held by
    the syntax guard below, not by this test."""
    import json
    import subprocess
    import sys

    archive = tmp_path / "x.mfbak"
    archive.write_bytes(b"not read: the verify coroutine is replaced")
    out = tmp_path / "records.json"
    driver = tmp_path / "unawaited_task.py"
    driver.write_text(f"PHI = {PHI!r}\n" + _UNAWAITED_TASK_DRIVER, encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(driver), str(archive), str(out)],
        cwd=tmp_path,  # away from the repo, so no stray ./messagefoundry.toml is picked up
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert out.is_file(), f"the driver did not finish: rc={proc.returncode}\n{proc.stderr}"
    result = json.loads(out.read_text(encoding="utf-8"))
    assert result["rc"] == 0, result
    messages = [r["message"] for r in result["records"] if r["level"] == "ERROR"]
    assert any("RuntimeError" in m and "never retrieved" in m for m in messages), (
        f"the unawaited task's exception never reached last_resort: {result['records']}\n"
        f"stderr: {proc.stderr}"
    )
    assert not any("DOE" in m or "JANE" in m for m in messages), "PHI reached the log unredacted"


_LOOP_STARTERS = frozenset({"run", "Runner", "new_event_loop"})


def _direct_loop_starts(source: str, filename: str) -> list[str]:
    """Every place ``source`` starts an event loop directly rather than through ``run_guarded``.

    A syntax check, so it covers at least these spellings and not every one: ``asyncio.run``,
    ``asyncio.Runner`` and ``asyncio.new_event_loop``, through an ``import asyncio as x`` alias or
    the ``asyncio.runners`` submodule too; a ``from asyncio[.runners] import`` of any of them; and
    any ``.run_until_complete(`` call."""
    import ast

    tree = ast.parse(source, filename=filename)
    aliases = {"asyncio"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            aliases.update(a.asname for a in node.names if a.name == "asyncio" and a.asname)

    def _rooted_in_asyncio(expr: ast.expr) -> bool:
        while isinstance(expr, ast.Attribute):
            expr = expr.value
        return isinstance(expr, ast.Name) and expr.id in aliases

    def _starts_a_loop(node: ast.AST) -> bool:
        if isinstance(node, ast.ImportFrom):
            return node.module in ("asyncio", "asyncio.runners", "asyncio.events") and any(
                a.name in _LOOP_STARTERS for a in node.names
            )
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            return False
        if node.func.attr == "run_until_complete":
            return True
        return node.func.attr in _LOOP_STARTERS and _rooted_in_asyncio(node.func.value)

    return [
        f"{filename}:{getattr(node, 'lineno', 0)}"
        for node in ast.walk(tree)
        if _starts_a_loop(node)
    ]


@pytest.mark.parametrize(
    "source",
    [
        "import asyncio\nasyncio.run(main())\n",
        "import asyncio as aio\naio.run(main())\n",
        "import asyncio\nwith asyncio.Runner() as r:\n    r.run(main())\n",
        "import asyncio\nasyncio.runners.run(main())\n",
        "from asyncio.runners import run\n",
        "from asyncio import Runner\n",
        "import asyncio\nasyncio.new_event_loop().run_until_complete(main())\n",
    ],
    ids=["run", "alias", "runner", "runners-module", "from-runners", "from-asyncio", "loop"],
)
def test_the_loop_guard_fires_on_each_spelling_it_claims(source: str) -> None:
    """Positive controls for the guard below: without them, its empty result could be a scanner
    that sees nothing."""
    assert _direct_loop_starts(source, "control.py"), f"the guard is blind to:\n{source}"


def test_no_engine_module_starts_a_loop_without_run_guarded() -> None:
    """Every loop the engine starts must come from ``last_resort.run_guarded`` (BACKLOG #1789),
    except the one uvicorn owns under ``serve``. A loop started directly gets the stdlib default
    handler, which prints a task's raw exception text. ``run_guarded`` itself is the one allowed
    site.

    Controls keep a zero from being a dead instrument. The scanner must find ``run_guarded``'s own
    two calls in the REAL tree, and it must fire on each spelling in the test above."""
    import messagefoundry

    root = Path(messagefoundry.__file__).resolve().parent
    allowed = root / "last_resort.py"
    files = sorted(root.rglob("*.py"))
    hits: list[str] = []
    allowed_hits: list[str] = []
    for path in files:
        found = _direct_loop_starts(path.read_text(encoding="utf-8"), str(path))
        (allowed_hits if path == allowed else hits).extend(found)

    assert len(files) > 100, f"scanned only {len(files)} files under {root}"
    assert len(allowed_hits) == 2, f"run_guarded's own calls were not found: {allowed_hits}"
    assert hits == [], (
        "a loop is started without the last-resort handler; use "
        f"messagefoundry.last_resort.run_guarded instead: {hits}"
    )
