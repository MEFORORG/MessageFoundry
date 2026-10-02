# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""CI legs that start ``messagefoundry serve`` sign in to it (vault BACKLOG #2719, stage A).

Seven workflow steps used to start ``messagefoundry serve`` with sign-in switched off, because the
load CLI and the smoke probes read the API with no session. They now provision one Administrator
before the engine starts and read the API as that account (``harness/load/rigadmin.py``).

Most of those legs run on a schedule, on dispatch and in the merge queue, and a ``pull_request``
event skips them. So a step that went back to the old shape would first show in the queue. These
checks read the workflow files, which a pull request does change, and fail there instead.

THEY READ TEXT, NOT A RUN. They show a step still calls the rig helper around its ``serve``. They do
not show the leg is green: its own result is that reading.

THEY COVER ``serve``, AND AT LEAST ONE ENGINE A WORKFLOW STARTS IS NOT ONE. ``ingress-rate-probe.yml``
runs ``harness/load/ingress_probe.py``, which builds the engine in-process through the test factory
with ``allow_no_auth=True`` and never runs ``serve``. Nothing here reads that path.
"""

from __future__ import annotations

from typing import Any

import pytest

_KEY = "MEFOR_SECURITY_REQUIRE_SIGN_IN"
#: How a step's script starts a real engine. The container smoke passes ``serve`` to the image's
#: entrypoint, so the bare subcommand is matched as well as the full command.
_SERVE = ("messagefoundry serve", "serve --config")
#: The provisioning COMMAND, as a module run (`-m harness.load.rigadmin`) and as the file the
#: container smoke mounts. Not the bare word: the smoke also names the file in a mount variable.
_PROVISION = ("rigadmin provision", "rigadmin.py provision")
#: The two ways a step reads the API signed in.
_SIGNED_IN = ("rigadmin run", "rigadmin get", "rigadmin.py get")


def _workflow_texts() -> dict[str, str]:
    from tests._workflow_contexts import WORKFLOWS

    found = {
        path.name: path.read_text(encoding="utf-8") for path in sorted(WORKFLOWS.glob("*.yml"))
    }
    assert len(found) >= 10, f"CONTROL FAILED: only {len(found)} workflow file(s) were read"
    return found


def _sets_sign_in(text: str) -> list[int]:
    """The 1-based lines of ``text`` that name the sign-in switch, in any of the forms a step uses:
    an ``env:`` entry, a ``docker run -e`` pair, or an NSSM environment string."""
    return [n for n, line in enumerate(text.splitlines(), 1) if _KEY in line]


def test_no_workflow_names_the_sign_in_switch() -> None:
    """No step hands ``serve`` the sign-in switch, so every ``serve`` a workflow starts runs with
    sign-in on, as shipped."""
    offenders = {
        name: lines for name, text in _workflow_texts().items() if (lines := _sets_sign_in(text))
    }
    assert not offenders, (
        f"these workflow lines set {_KEY}. A leg that starts an engine provisions the rig "
        f"Administrator and signs in (harness/load/rigadmin.py): {offenders}"
    )


def test_the_switch_scan_sees_each_form_a_step_has_used() -> None:
    """CONTROL: the scan above must be able to fail, on each shape the seven steps carried."""
    for planted in (
        f'          {_KEY}: "false"  # the load CLI polls /stats\n',
        f"            -e {_KEY}=false \\\n",
        f'            "{_KEY}=false" `\n',
    ):
        assert _sets_sign_in("name: x\n" + planted) == [2], planted
    assert _sets_sign_in("name: x\n          MEFOR_SECURITY_REQUIRE_MFA: 'false'\n") == []


def _steps(workflow: str) -> list[tuple[str, str, str]]:
    """``(job key, step name, script)`` for every step of ``workflow`` that has a script. Comment
    lines are dropped, so a needle cannot be met by prose about it."""
    from tests._workflow_contexts import jobs_of

    out: list[tuple[str, str, str]] = []
    jobs: dict[str, dict[str, Any]] = jobs_of(workflow)
    for key, job in jobs.items():
        for step in job.get("steps") or []:
            run = str(step.get("run") or "")
            script = "\n".join(
                line for line in run.splitlines() if not line.lstrip().startswith("#")
            )
            if script:
                out.append((key, str(step.get("name") or "<unnamed>"), script))
    return out


def _first(script: str, needles: tuple[str, ...]) -> int:
    """Where the earliest of ``needles`` starts in ``script``, or -1."""
    hits = [at for needle in needles if (at := script.find(needle)) != -1]
    return min(hits, default=-1)


def _order_problem(script: str) -> str | None:
    """What is wrong with the order of a serving step's script, or ``None``.

    The engine refuses to start with sign-in on and no Administrator, and a session exists only
    once it is up. So the order is: provision, serve, read signed in."""
    provision, serve, read = (_first(script, n) for n in (_PROVISION, _SERVE, _SIGNED_IN))
    if provision == -1:
        return "never provisions the rig Administrator (rigadmin provision)"
    if provision > serve:
        return "serves before it provisions the rig Administrator"
    if read == -1:
        return "never reads the API signed in (rigadmin run, rigadmin get)"
    if read < serve:
        return "reads the API before it serves"
    return None


@pytest.mark.parametrize("workflow", ["ci.yml", "benchmark.yml"])
def test_a_step_that_serves_provisions_first_and_reads_signed_in(workflow: str) -> None:
    pytest.importorskip("yaml")
    serving = [(job, name, s) for job, name, s in _steps(workflow) if _first(s, _SERVE) != -1]
    assert serving, f"CONTROL FAILED: no step of {workflow} starts an engine"
    problems = {
        f"{job} / {name}": problem
        for job, name, script in serving
        if (problem := _order_problem(script)) is not None
    }
    assert not problems, f"{workflow}: {problems}"


def test_the_order_check_can_fail_on_each_arm() -> None:
    """CONTROL, on the container smoke's shape, where the helper's file name also sits in a mount
    variable ABOVE everything. An order check that anchors on that word passes all four."""
    mount = 'rig_mount="$PWD/harness/load/rigadmin.py:/rig/rigadmin.py:ro"\n'
    provision = "docker run --rm --entrypoint python image /rig/rigadmin.py provision\n"
    serve = "docker run -d --name mefor image serve --config /config\n"
    read = "docker exec mefor python /rig/rigadmin.py get --field total /messages\n"
    assert _order_problem(mount + provision + serve + read) is None
    assert "serves before" in str(_order_problem(mount + serve + provision + read))
    assert "never provisions" in str(_order_problem(mount + serve + read))
    assert "never reads" in str(_order_problem(mount + provision + serve))
    assert "before it serves" in str(_order_problem(mount + provision + read + serve))


def test_the_serving_steps_are_the_ones_this_was_written_for() -> None:
    """Which jobs serve, so a new one is met here and not first in the merge queue.

    Six of the seven steps match. The seventh, the Windows service smoke, starts its engine through
    NSSM in a later step than the one that installs it, and is pinned on its own below."""
    pytest.importorskip("yaml")
    serving = {
        workflow: sorted(job for job, _, s in _steps(workflow) if _first(s, _SERVE) != -1)
        for workflow in ("ci.yml", "benchmark.yml")
    }
    assert serving == {
        "ci.yml": ["docker-smoke", "load-test", "load-test-sqlserver"],
        "benchmark.yml": ["baseline-postgres", "baseline-sqlite", "baseline-sqlserver"],
    }, serving


def test_a_benchmark_step_fails_when_the_rig_never_signed_in() -> None:
    """A benchmark step does not propagate the load CLI's own exit, on purpose. ``rigadmin run``
    exits 4 when the rig could not sign in, which is not the load CLI's verdict: no load ran. The
    step must fail on that code, or a refused sign-in is a green run with no report."""
    pytest.importorskip("yaml")
    serving = [(job, s) for job, _, s in _steps("benchmark.yml") if _first(s, _SERVE) != -1]
    assert len(serving) == 3, [job for job, _ in serving]
    for job, script in serving:
        assert "rig_rc=$?" in script, f"{job} no longer captures the rig's exit code"
        assert script.rstrip().endswith('[ -n "$ready" ] && [ "$rig_rc" -ne 4 ]'), (
            f"{job} no longer ends on the gate that fails a rig that never signed in"
        )


def test_the_windows_service_smoke_provisions_before_its_first_start_and_reads_signed_in() -> None:
    pytest.importorskip("yaml")
    steps = [(name, s) for job, name, s in _steps("ci.yml") if job == "windows-service-smoke"]
    names = [name for name, _ in steps]
    scripts = dict(steps)
    install = scripts["Install the service"]
    assert "-m harness.load.rigadmin provision" in install, (
        "the install step no longer provisions the rig Administrator before the service starts"
    )
    assert 'nssm.exe" start MessageFoundry' not in install, (
        "the install step now starts the service; provisioning must still come first"
    )
    assert names.index("Install the service") < names.index("Start and verify /health")
    read = scripts["Send an MLLP message and confirm it was recorded"]
    assert "-m harness.load.rigadmin get" in read and "/messages" in read, (
        "the /messages read no longer signs in as the rig Administrator"
    )
