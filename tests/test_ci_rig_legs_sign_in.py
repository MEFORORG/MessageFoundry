# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""CI legs that start a real engine sign in to it (vault BACKLOG #2719, stage A).

Seven workflow steps used to start ``messagefoundry serve`` with sign-in switched off, because the
load CLI and the smoke probes read the API with no session. They now provision one Administrator
before the engine starts and read the API as that account (``harness/load/rigadmin.py``).

Most of those legs run on a schedule, on dispatch and in the merge queue, and a ``pull_request``
event skips them. So a step that went back to the old shape would first show in the queue. These
checks read the workflow files, which a pull request does change, and fail there instead.

THEY READ TEXT, NOT A RUN. They show a step still calls the rig helper before it serves. They do not
show the leg is green: its own result is that reading.
"""

from __future__ import annotations

from typing import Any

import pytest

_KEY = "MEFOR_SECURITY_REQUIRE_SIGN_IN"
#: How a step's script starts a real engine. The container smoke passes ``serve`` to the image's
#: entrypoint, so the bare subcommand is matched as well as the full command.
_SERVE = ("messagefoundry serve", "serve --config")


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
    """No step sets sign-in, so every engine a workflow starts runs with it on, as shipped."""
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


@pytest.mark.parametrize("workflow", ["ci.yml", "benchmark.yml"])
def test_a_step_that_serves_provisions_the_rig_administrator_first(workflow: str) -> None:
    """The engine refuses to start with sign-in on and no Administrator, so the order matters:
    provision, then serve."""
    pytest.importorskip("yaml")
    serving = [(job, name, s) for job, name, s in _steps(workflow) if _first(s, _SERVE) != -1]
    assert serving, f"CONTROL FAILED: no step of {workflow} starts an engine"
    for job, name, script in serving:
        provision = script.find("rigadmin")
        assert provision != -1 and "provision" in script[provision:], (
            f"{workflow} {job} / {name!r} starts an engine and never provisions the rig "
            "Administrator (python -m harness.load.rigadmin provision)"
        )
        assert provision < _first(script, _SERVE), (
            f"{workflow} {job} / {name!r} serves before it provisions the rig Administrator"
        )


def test_the_serving_steps_are_the_ones_this_was_written_for() -> None:
    """The count of serving steps, so a new one is met here and not first in the merge queue.

    Four ``serve`` steps in ci.yml would be five: the Windows service smoke starts its engine
    through NSSM, in a later step than the one that installs it, and is pinned on its own below."""
    pytest.importorskip("yaml")
    serving = {
        workflow: sorted(job for job, _, s in _steps(workflow) if _first(s, _SERVE) != -1)
        for workflow in ("ci.yml", "benchmark.yml")
    }
    assert serving == {
        "ci.yml": ["docker-smoke", "load-test", "load-test-sqlserver"],
        "benchmark.yml": ["baseline-postgres", "baseline-sqlite", "baseline-sqlserver"],
    }, serving


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
