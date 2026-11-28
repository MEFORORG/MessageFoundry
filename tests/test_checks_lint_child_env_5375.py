# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5375, through the public ``run_checks``: the check gate's three advisory lint children
are started from the program the gate's own locator returns, never a bare name a ``PATH`` search
resolves, mypy as ``python -P -m mypy``, and with no engine secret in their environment.

What this pins, and what it does not: ``_ruff_binary`` is replaced by a fake that returns an
absolute path, so whether the real locator returns an absolute path is pinned separately, by
``test_checks.py::test_ruff_binary_is_absolute_when_found``. ``shutil.which`` is replaced by one
that returns the bare name, so code that locates a tool through it starts a bare name and fails
here.

This lives in its own file, apart from ``test_checks.py``, so it can be run against the code
before the fix: that file's module-level ``skipif`` reads ``checks._ruff_binary``, which the
unfixed module does not define, so the whole file fails to collect there. Measured failing at
``04586ba4ae8``, the first parent of ``e41e3451ee3``, where the child got the bare name ``ruff``
and the caller's whole environment, and passing on the fixed code."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

import messagefoundry.checks as checks
from messagefoundry.checks import run_checks

#: At least one variable per class the child must not see, the lower-case engine prefix included.
#: The test reads names only, so each value is a plain placeholder, not a secret-shaped string.
_SECRETS = {
    "MEFOR_STORE_ENCRYPTION_KEY": "placeholder",
    "mefor_lower_b20009": "placeholder",
    "VAULT_TOKEN": "placeholder",
    "PGPASSWORD": "placeholder",
    "CI_DEPLOY_TOKEN_B20009": "placeholder",
}


def _lint_tool(cmd: list[str]) -> str | None:
    """Which lint leg ``cmd`` starts, or ``None`` for a child some other leg starts."""
    module = cmd[cmd.index("-m") + 1] if "-m" in cmd[:-1] else Path(cmd[0]).name.lower()
    if module.startswith("mypy"):
        return "mypy"
    if module.startswith("ruff"):
        return "ruff-security" if "--select" in cmd else "ruff"
    return None


def test_run_checks_lint_children_start_by_absolute_path_with_no_engine_secret(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    for name, value in _SECRETS.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("MYPYPATH", "stubs")
    monkeypatch.setenv("PYTHONIOENCODING", "ascii")
    calls: dict[str, list[tuple[list[str], dict[str, str]]]] = {}

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        tool = _lint_tool(list(cmd))
        assert tool is not None, f"unexpected child: {cmd}"
        # A program named through executable= or a shell is located by the OS, not by argv[0];
        # a child with no env= inherits the caller's whole environment.
        assert kwargs.get("executable") is None and not kwargs.get("shell"), cmd
        assert kwargs.get("env") is not None, f"{cmd} inherits the whole environment"
        calls.setdefault(tool, []).append((list(cmd), dict(kwargs["env"])))
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    # The tool-locating seams differ before and after the fix. The fixed code has _tool_command
    # and must then have both seams it reads, so each is patched strictly there; on the unfixed
    # code neither exists, and it locates a tool through shutil.which.
    fixed = hasattr(checks, "_tool_command")
    program = str(tmp_path / "ruff.exe")
    monkeypatch.setattr(checks, "_ruff_binary", lambda: program, raising=fixed)
    monkeypatch.setattr(checks, "_tool_installed", lambda _module: True, raising=fixed)
    monkeypatch.setattr(shutil, "which", lambda name, *_a, **_k: name)

    # An empty config directory: the lint legs start the same way, without the sample graph.
    config_dir = tmp_path / "cfg"
    config_dir.mkdir()
    report = run_checks(config_dir, messages_dir=None, run_lint=True)

    by_name = {r.name: r for r in report.results}
    started = {tool: [cmd for cmd, _env in found] for tool, found in calls.items()}
    for tool in ("ruff", "mypy", "ruff-security"):
        assert by_name[tool].skipped is False, by_name[tool].detail
        assert len(started.get(tool, [])) == 1, started  # commands only, never env values

    config = str(config_dir)
    ruff_cmd = calls["ruff"][0][0]
    assert ruff_cmd == [program, "check", config]
    security_cmd = calls["ruff-security"][0][0]
    assert security_cmd[:2] == [program, "check"] and security_cmd[-1] == config
    mypy_cmd = calls["mypy"][0][0]
    assert mypy_cmd[0] == sys.executable and Path(mypy_cmd[0]).is_absolute()
    assert "-P" in mypy_cmd
    assert mypy_cmd[-4:] == ["-m", "mypy", "--config-file=", config]

    for [(cmd, env)] in calls.values():
        upper = {name.upper() for name in env}
        assert not any(name.startswith("MEFOR_") for name in upper), cmd
        assert {name.upper() for name in _SECRETS}.isdisjoint(upper), cmd
        assert env.get("MYPYPATH") == "stubs", cmd  # the tools' own variables still cross
        assert env.get("PYTHONIOENCODING") == "utf-8", cmd  # pinned over an inherited value
        assert "PATH" in upper, cmd
