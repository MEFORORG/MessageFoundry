# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5375: the check gate's advisory lint children start by an absolute program path and
get no engine secret, measured through the public ``run_checks``.

This lives in its own file, apart from ``test_checks.py``, so it can be run against the code
before the fix: that file's module-level ``skipif`` reads ``checks._ruff_binary``, which the
unfixed module does not define, so the whole file fails to collect there. Measured failing at
``04586ba4ae8``, the first parent of ``e41e3451ee3``, where the child got the bare name ``ruff``
and the caller's whole environment, and passing on the fixed code."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

import messagefoundry.checks as checks
from messagefoundry.checks import run_checks

SAMPLES_CONFIG = Path(__file__).resolve().parents[1] / "samples" / "config"

#: One variable per class the child must not see. The test reads names only, so each value is a
#: plain placeholder rather than a secret-shaped string.
_SECRETS = {
    "MEFOR_STORE_ENCRYPTION_KEY": "placeholder",
    "VAULT_TOKEN": "placeholder",
    "PGPASSWORD": "placeholder",
    "CI_DEPLOY_TOKEN_B20009": "placeholder",
}


def test_run_checks_lint_children_start_by_absolute_path_with_no_engine_secret(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    for name, value in _SECRETS.items():
        monkeypatch.setenv(name, value)
    calls: list[tuple[list[str], dict[str, str]]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append((list(cmd), dict(kwargs["env"])))
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    # The tool-locating seams differ before and after the fix, so each is patched with
    # raising=False: the unfixed code resolves through shutil.which, the fixed code through
    # _ruff_binary and _tool_installed. Either way every tool is found and started.
    program = str(tmp_path / "ruff.exe")
    monkeypatch.setattr(checks, "_ruff_binary", lambda: program, raising=False)
    monkeypatch.setattr(checks, "_tool_installed", lambda _module: True, raising=False)
    monkeypatch.setattr(shutil, "which", lambda *_a, **_k: program)

    report = run_checks(SAMPLES_CONFIG, messages_dir=None, run_lint=True)

    by_name = {r.name: r for r in report.results}
    for tool in ("ruff", "mypy", "ruff-security"):
        assert by_name[tool].skipped is False, by_name[tool].detail
    assert len(calls) >= 3
    for cmd, env in calls:
        assert Path(cmd[0]).is_absolute(), cmd
        upper = {name.upper() for name in env}
        assert not any(name.startswith("MEFOR_") for name in upper), cmd
        assert {"VAULT_TOKEN", "PGPASSWORD", "CI_DEPLOY_TOKEN_B20009"}.isdisjoint(upper), cmd
        assert "PATH" in upper
