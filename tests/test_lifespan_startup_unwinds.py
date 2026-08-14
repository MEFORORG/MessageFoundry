# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""BACKLOG #1257: a startup failure after ``engine.start()`` must let the PROCESS exit.

The lifespan's teardown is complete -- it stops the engine (which closes the store), both
notifiers, the upload-retention runner and all three background tasks. It was simply
UNREACHABLE from a startup failure: its ``try:`` began at the ``yield``, so it guarded the
RUNNING phase and never the STARTUP phase. Everything brought up between ``engine.start()``
and the yield was therefore abandoned in place.

What that costs is the process itself, not just tidiness. ``engine.stop()`` ends in
``store.close()``, and aiosqlite's connection worker is a NON-DAEMON thread -- so an
unclosed store means interpreter shutdown blocks forever. uvicorn refuses correctly and
legibly, prints ``Application startup failed. Exiting.``, raises ``SystemExit(3)`` -- and
then the process stays alive. A hung refusal, not a silent one.

THE ASSERTION HERE IS DELIBERATELY NARROW: **the process terminates**. Not that the error
prints, not that ``SystemExit`` is raised. Both of those were measured TRUE while the process
went on living for 90 seconds, so neither discriminates -- a test asserting either would have
passed against the defect.

The failure is injected by patching a real call site inside the span rather than by driving
any one feature's logic, so this stays a test about UNWINDING and does not fail when the gate
that happens to sit there changes.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

# The defect is an INDEFINITE hang, so any finite bound discriminates; this is sized to stay
# UNDER the suite's own `--timeout=60` watchdog. That ordering is the whole point: at 90s the
# watchdog fired first and the failure surfaced as a raw traceback from inside `communicate`,
# with this test's diagnosis never reaching the report. A bound above the watchdog is dead code.
_EXIT_TIMEOUT_SECONDS = 30.0

_CHILD = """
import sys
from pathlib import Path

import uvicorn

import messagefoundry.api.app as appmod
from messagefoundry.api import create_managed_app
from messagefoundry.config.settings import AuthSettings


async def _boom(*args: object, **kwargs: object) -> None:
    raise RuntimeError("PROBE: deliberate failure in the post-engine startup span")


# A real call site inside the span (after engine.start(), before the yield). Patching the
# function rather than arranging its preconditions keeps this about unwinding.
appmod._assert_security_notice_is_deliverable = _boom  # type: ignore[assignment]

app = create_managed_app(
    db_path=Path(sys.argv[1]) / "probe.db",
    poll_interval=0.05,
    auth_settings=AuthSettings(enabled=True),
)

print("PROBE: starting uvicorn", flush=True)
try:
    # port 0: nothing binds a real port, and startup fails before serving regardless.
    uvicorn.run(app, host="127.0.0.1", port=0, log_level="error")
except SystemExit:
    # uvicorn's own refusal. Caught so the child returns normally -- interpreter shutdown then
    # has to JOIN every non-daemon thread, which is precisely the condition under test.
    print("PROBE: uvicorn refused (SystemExit)", flush=True)
print("PROBE: reached end of script", flush=True)
"""


def test_a_startup_failure_after_engine_start_lets_the_process_exit(tmp_path: Path) -> None:
    child = tmp_path / "child.py"
    child.write_text(textwrap.dedent(_CHILD), encoding="utf-8")

    proc = subprocess.Popen(
        [sys.executable, str(child), str(tmp_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    try:
        out, _ = proc.communicate(timeout=_EXIT_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()
        pytest.fail(
            "the process did NOT exit within "
            f"{_EXIT_TIMEOUT_SECONDS}s after a startup failure -- a hung refusal. "
            f"child output:\n{out}"
        )

    # POSITIVE CONTROLS on the injection. Without these the timeout check alone is satisfied by a
    # child that exited for any reason at all -- including never reaching the span, or dying before
    # uvicorn started. Each line below pins one step of the path that must actually have run.
    #
    # `returncode is not None` is NOT among them: communicate() always sets it, so it asserts
    # nothing about the subject.
    assert "PROBE: starting uvicorn" in out, f"child never reached uvicorn:\n{out}"
    assert "PROBE: uvicorn refused (SystemExit)" in out, (
        f"the injected failure did not produce uvicorn's refusal -- this test no longer exercises "
        f"a startup failure at all:\n{out}"
    )
    assert "PROBE: reached end of script" in out, (
        f"the child did not return normally from the refusal, so what this measured is some other "
        f"exit path:\n{out}"
    )

    # THE TEARDOWN MUST NOT MASK THE STARTUP ERROR. This is the regression test for hoisting the
    # five teardown handles above the try. Measured by deleting one of them: the finally reaches
    # those names BEFORE it reaches engine.stop(), so an unbound one raises UnboundLocalError
    # inside the teardown, aborts it there, and the store never closes -- the hang comes straight
    # back, with the real error replaced. So the hoist is part of the fix, not a tidiness pass.
    assert "deliberate failure in the post-engine startup span" in out, (
        f"the original startup error did not survive teardown -- something in the finally replaced "
        f"it:\n{out}"
    )
