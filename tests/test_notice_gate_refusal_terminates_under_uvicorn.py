# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1020: the REAL notice gate's refusal must terminate the process under uvicorn.

#1020 carries an explicit non-closure rider -- the refusal has to be *demonstrated* to terminate
under the runner that ships, not inferred from a mechanism. Two tests already stand near this and
neither discharges it, which is why a third one earns its runtime:

* ``tests/test_security_notice_deliverability.py::test_the_LIFESPAN_refuses_and_not_merely_the_predicate``
  drives the real refusal, but through ``app.router.lifespan_context`` -- no uvicorn, no process.
* ``tests/test_lifespan_startup_unwinds.py`` runs uvicorn in a subprocess and asserts the process
  exits, but it PATCHES ``_assert_security_notice_is_deliverable`` with a raising stub. That is
  deliberate and correct for its own subject (BACKLOG #1257 is about unwinding, and it must not
  fail when the gate that happens to sit there changes) -- and it means the thing that raised was
  never the gate. **Do not weaken or reuse it.** This file arranges the gate's real preconditions
  instead and lets the shipped code do the refusing.

ADR 0167 records a second open question under *"What is NOT demonstrated"*: its exit-code arms were
measured on a minimal repro that BACKLOG #1257's fix does not touch, so the REAL gate's exit code
inside a lifespan that now unwinds properly had not been measured by anyone. The enforce arm below
measures it, which is why it pins the code rather than only the fact of exiting.

WHAT THE CONTROL ARM ESTABLISHES, STATED NO LARGER THAN IT IS. A child that exits is equally
consistent with an app that can never start at all, and that failure would pass a one-armed test
forever. The warn arm is the same app, the same gate and the same store state with the enforcement
dial moved, and it reaches a RUNNING server -- so "it exited" was not the only outcome this rig
could produce. **It is NOT a one-variable experiment**, and an earlier draft of this docstring
claimed it was. The arms also differ in uvicorn ENTRY POINT, and that difference is forced: only
``uvicorn.run`` turns a startup failure into the exit code under test, and it never hands back the
``Server`` a self-stopping control needs. So the control's claim is "this app reaches RUNNING under
uvicorn", not "the dial is the only thing that changed".

The app is built inline rather than imported from
``tests/test_security_notice_deliverability.py::_phi_app``, which builds the identical shape. The
child runs with ``sys.path[0]`` at the temp directory, so reusing that helper means plumbing the
repo root into the subprocess for one call. That is a deliberate copy, not an oversight -- if the
"#1020 app shape" changes, both sites move.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

# Sized to stay UNDER the suite's own ``--timeout=60`` watchdog, for the reason
# ``tests/test_lifespan_startup_unwinds.py`` records: the defect here is an INDEFINITE hang, so any
# finite bound discriminates, but a bound above the watchdog is dead code -- the watchdog fires
# first and the diagnosis below never reaches the report.
_EXIT_TIMEOUT_SECONDS = 30.0

# uvicorn's own startup-failure code (``uvicorn.main.STARTUP_FAILURE``). Written as a literal on
# purpose: importing the constant would make the assertion re-derive the number it exists to
# defend, and docs/DEPLOYMENT.md states this number to operators. If uvicorn ever changes it, the
# doc is wrong and this test is the thing that says so.
_UVICORN_STARTUP_FAILURE = 3

# The warn arm's own exit code. Distinct from 0, 1, 2 and 3 so it cannot be reached by uvicorn, by
# an unhandled exception, or by a refusal on either ladder. Passed to the child rather than spelled
# there too, so the number and the reasoning above stay in one place.
_CONTROL_EXIT = 99

# The identifying clause of the gate's refusal (messagefoundry/api/app.py). Copied, because the
# shipped message is an inline f-string body with no exported constant -- see this file's PR for
# the unfiled cleanup note.
_REFUSAL = "no enabled Administrator has a notification address"

_CHILD = """
import asyncio
import logging
import sys
from pathlib import Path

import uvicorn

from messagefoundry.api import create_managed_app
from messagefoundry.config.settings import (
    AlertsSettings,
    AuthSettings,
    SecurityEnforcement,
    SecuritySettings,
    StoreSettings,
)

_TMP, _ARM, _CONTROL_EXIT = sys.argv[1], sys.argv[2], int(sys.argv[3])

# A real handler, so the gate's warn-side log line goes somewhere the parent can read WITHOUT
# depending on logging.lastResort. create_managed_app configures no handlers (the product does that
# in messagefoundry/logging_setup.py, which serve calls and this child does not), and uvicorn's own
# dictConfig only touches the uvicorn* loggers.
logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s %(message)s")

# SMTP is fully wired on purpose: the transport gate in ``__main__`` would call this channel
# healthy. A green transport over an undeliverable notice is the whole of #1020. The store starts
# empty, so the only account that will exist is the bootstrap administrator the lifespan itself
# mints -- created with no address, which is the genuine first-run state rather than a synthetic
# row resembling it.
app = create_managed_app(
    # A keyless store under the audited at-rest opt-out, which BACKLOG #1916 makes the lifespan
    # itself enforce whenever security_settings is passed, as serve always passes it.
    store_settings=StoreSettings(path=str(Path(_TMP) / "phi.db"), allow_unencrypted_phi=True),
    poll_interval=0.05,
    auth_settings=AuthSettings(enabled=True, notify_security_events=True),
    alerts_settings=AlertsSettings(
        security_notifications_required=True,
        email_smtp_host="smtp.example.test",
        email_from="alerts@example.test",
    ),
    security_settings=SecuritySettings(
        enforcement=(
            SecurityEnforcement.ENFORCE if _ARM == "enforce" else SecurityEnforcement.WARN
        ),
        allow_unencrypted_phi_under_strict_enforcement=True,
    ),
)


def _enforce_arm() -> int:
    # uvicorn.run is what converts a lifespan startup failure into the process exit code, so the
    # arm that measures that code has to go through it. port 0: nothing binds a real port, and
    # startup fails before serving regardless.
    try:
        uvicorn.run(app, host="127.0.0.1", port=0, log_level="error")
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
        print("PROBE: uvicorn refused (SystemExit %d)" % code, flush=True)
        return code
    return 0


def _warn_arm() -> int:
    # The control cannot use uvicorn.run: that wrapper never hands back the Server, and stopping
    # this arm needs one. Same library, same app, same gate -- a different entry point.
    async def _serve_then_stop() -> None:
        server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error"))
        task = asyncio.ensure_future(server.serve())
        # task.done() matters: without it a crashed serve() spins here until the parent's bound
        # instead of failing fast.
        while not server.started and not task.done():
            await asyncio.sleep(0.05)
        if server.started:
            print("PROBE: server STARTED", flush=True)
        server.should_exit = True
        await task

    asyncio.run(_serve_then_stop())
    return _CONTROL_EXIT


print("PROBE: starting uvicorn", flush=True)
_code = _enforce_arm() if _ARM == "enforce" else _warn_arm()
# Printed BEFORE the exit, and the exit is the last thing this script does. Returning normally from
# the refusal is what forces interpreter shutdown to JOIN every non-daemon thread -- aiosqlite's
# connection worker is one, and that join is precisely the condition under test.
print("PROBE: reached end of script", flush=True)
sys.exit(_code)
"""


def _run_child(tmp_path: Path, arm: str) -> tuple[int, str]:
    child = tmp_path / f"child_{arm}.py"
    # Written to a real file rather than passed with -c: a traceback then carries a filename
    # instead of "<string>", and the script survives in tmp_path for post-mortem.
    child.write_text(_CHILD, encoding="utf-8")
    try:
        done = subprocess.run(
            [sys.executable, str(child), str(tmp_path), arm, str(_CONTROL_EXIT)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_EXIT_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        pytest.fail(
            f"the {arm} child did NOT exit within {_EXIT_TIMEOUT_SECONDS}s -- a hung refusal is "
            f"strictly worse than the mis-report #1020 exists to correct, because an operator can "
            f"see a wrong readiness answer but not a process that never finishes starting. "
            f"child output:\n{exc.output}"
        )
    return done.returncode, done.stdout


def test_the_real_gate_refuses_under_uvicorn_and_the_process_exits(tmp_path: Path) -> None:
    """The #1020 rider, discharged by demonstration rather than by inference."""
    code, out = _run_child(tmp_path, "enforce")

    # TWO INDEPENDENT FACTS THE EXIT CODE CANNOT CARRY. Without them, "it exited 3" is satisfied by
    # a child that died before ever reaching the gate.
    assert "PROBE: starting uvicorn" in out, f"the child never reached uvicorn:\n{out}"
    assert _REFUSAL in out, (
        f"the gate's own refusal text is absent, so whatever stopped this process was NOT the "
        f"notice gate and this test measures something else:\n{out}"
    )

    # THE TWO BELOW ARE ORDERING AIDS, NOT INDEPENDENT FACTS -- labelled so nobody reads them as
    # extra coverage. The only path to a non-zero code is the except branch that prints them, so
    # the exit-code assertion already implies both. They earn their place by failing FIRST and more
    # legibly than a bare number when the child takes some other path.
    assert "PROBE: uvicorn refused (SystemExit" in out, (
        f"the refusal did not reach uvicorn's startup-failure path:\n{out}"
    )
    assert "PROBE: reached end of script" in out, (
        f"the child did not return normally from the refusal, so what this measured is some other "
        f"exit path:\n{out}"
    )

    # ADR 0167's open re-measurement: the real gate, inside a lifespan that unwinds properly, still
    # exits 3. docs/DEPLOYMENT.md documents that number; this is what keeps the two agreeing.
    assert code == _UVICORN_STARTUP_FAILURE, (
        f"a startup-stage refusal exited {code}, not {_UVICORN_STARTUP_FAILURE} -- "
        f"docs/DEPLOYMENT.md and ADR 0167 both record 3:\n{out}"
    )

    # The teardown must not MASK the startup error. Presence of the refusal text does not settle
    # this: CPython chains, so an exception raised inside the ``finally`` carries the original as
    # ``__context__`` and Starlette formats the whole chain. The banner is the discriminator.
    assert "During handling of the above exception" not in out, (
        f"something raised while handling the refusal, so the operator is shown the teardown's "
        f"error instead of the real cause:\n{out}"
    )


def test_the_same_app_under_warn_reaches_a_running_server(tmp_path: Path) -> None:
    """POSITIVE CONTROL on the arm above: a non-refusal is observable in the identical rig."""
    code, out = _run_child(tmp_path, "warn")

    assert "PROBE: server STARTED" in out, (
        f"the control never reached a RUNNING server, so the refusal above is equally consistent "
        f"with an app that cannot start for an unrelated reason:\n{out}"
    )
    assert _REFUSAL in out, (
        f"warn is supposed to log the same finding rather than raise on it; its absence means the "
        f"control started for the wrong reason -- a deliverable admin, not a downgraded dial:\n{out}"
    )
    assert code == _CONTROL_EXIT, (
        f"the control exited {code}, not {_CONTROL_EXIT} -- it did not complete its own path:\n{out}"
    )


def test_the_deployment_doc_states_the_same_exit_code() -> None:
    """The number above is an operator-facing claim, so nothing may move one side of it alone.

    ``docs/DEPLOYMENT.md`` tells operators a startup-stage refusal exits 3. Nothing else executes
    that document, so without this the runner could change its code and the doc would go on saying
    3 with every test green.
    """
    doc = Path(__file__).resolve().parents[1] / "docs" / "DEPLOYMENT.md"
    text = doc.read_text(encoding="utf-8")
    heading = f"a startup-stage refusal exits **{_UVICORN_STARTUP_FAILURE}**"
    assert heading in text, (
        f"docs/DEPLOYMENT.md no longer states {heading!r}. Either the exit code moved and the doc "
        f"was not updated, or the section was reworded -- both need a human."
    )
    # POSITIVE CONTROL on the instrument: a substring search that finds nothing proves nothing
    # unless it can find something. The pre-existing exit-2 statements are the fixed point.
    assert "(exit 2)" in text, (
        "the exit-2 statements this section sits beside are gone, so the search above is being run "
        "against a document that no longer has the shape it is checking"
    )
