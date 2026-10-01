# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""CI's ``test`` legs install the ``[sftp]`` extra, and this fails if they stop (BACKLOG #2084).

The real-paramiko tests (a loopback SSH handshake, paramiko's own algorithm lists, the RSA key
floor, the stalled-channel bounds) all skip when ``import paramiko`` fails. Before #2084 no CI leg
installed the extra, so every one of them skipped in CI and a skip reads as green. Four of them had
rotted unseen by the time the extra went on.

The guard works by mechanism, not by test name. Every real-paramiko test skips through the same
door, a failed ``import paramiko``, so proving the import works on the leg proves none of them can
skip there for that reason. That covers tests added later without listing them here.

The leg arms the runtime check by setting ``MEFOR_REQUIRE_SFTP_EXTRA=1`` on its pytest step.
Everywhere else the check skips, because a dev install without the extra is normal. The static
check below keeps the arming itself from being dropped, since dropping the variable would turn the
runtime check into a silent skip, the very shape this file exists to stop.
"""

from __future__ import annotations

import functools
import os
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from messagefoundry.transports import remotefile

_CI = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "ci.yml"
_ARM = "MEFOR_REQUIRE_SFTP_EXTRA"


def test_the_sftp_extra_is_importable_where_the_leg_requires_it() -> None:
    if os.environ.get(_ARM) != "1":
        pytest.skip(f"{_ARM} is not 1, so this is not a leg that promises the [sftp] extra")
    # The engine's own lazy import: a failure raises its RuntimeError, which names the install fix.
    paramiko = remotefile._import_paramiko()
    assert hasattr(paramiko, "Transport"), "paramiko imported but is not the SSH library"


@functools.cache
def _test_job_steps() -> list[dict[str, Any]]:
    # Scoped to jobs.test on purpose. The raw-line readers in other tests take the widest install
    # line in the whole file, which would still pass if only another job kept the extra.
    workflow = yaml.safe_load(_CI.read_text(encoding="utf-8"))
    steps: list[dict[str, Any]] = workflow["jobs"]["test"]["steps"]
    return steps


def test_the_ci_test_job_installs_the_sftp_extra() -> None:
    installs = [
        s["run"]
        for s in _test_job_steps()
        if "run" in s and "uv pip install" in s["run"] and "constraints.lock -e" in s["run"]
    ]
    # CONTROL: the step this reads must still be found, or an empty list passes the check below.
    assert len(installs) == 1, f"expected one project install step in jobs.test, found {installs}"
    m = re.search(r'-e "\.\[([^\]]+)\]"', installs[0])
    assert m is not None, f'no -e ".[...]" extras list in the jobs.test install step: {installs[0]}'
    extras = [e.strip() for e in m.group(1).split(",")]
    assert "sftp" in extras, f"jobs.test installs {extras}, without sftp (BACKLOG #2084)"


def test_the_ci_test_job_arms_the_runtime_check() -> None:
    tests_steps = [s for s in _test_job_steps() if s.get("id") == "tests"]
    assert len(tests_steps) == 1, "jobs.test has no single step with id: tests"
    env = tests_steps[0].get("env") or {}
    assert str(env.get(_ARM)) == "1", (
        f"the pytest step in jobs.test must set {_ARM}: '1', or the runtime check skips silently"
    )
