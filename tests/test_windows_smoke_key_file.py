# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The Windows service smoke keeps its connection key where ``enforce`` accepts it (BACKLOG #3402).

The samples graph deploys ``OB_IMMUNIZATION_REGISTRY``, a SOAP outbound with a client key, so the
smoke mints a throwaway pair for it. ``enforce`` refuses a connection's key file that a broad group
can read. The smoke used to mint the pair under ``RUNNER_TEMP``, which grants ``BUILTIN\\Users``
read, and every leg's service then refused to start (CI run 39539448967). The pair now goes in the
data directory ``install-service.ps1`` locks, and the step runs the engine's own check on the key.

``windows-service-smoke`` runs only in the merge queue, so these read the workflow text and fail at
the pull request instead. They show where the step mints the key and that it checks it. They do not
show the leg is green: its own result is that reading. That a key under the locked data directory
passes the check is measured in ``tests/test_service_install_manifest.py``.
"""

from __future__ import annotations

import functools
import re
from pathlib import Path

import pytest

_JOB = "windows-service-smoke"
_STEP = "Install the service"
#: install-service.ps1's default -DataDir, which its Set-SecureDataDirAcl locks.
_DATA_DIR = "C:\\ProgramData\\MessageFoundry"
#: Built by hand rather than through messagefoundry.service, so this stays a tooling test.
_INSTALLER = Path(__file__).resolve().parents[1] / "scripts" / "service" / "install-service.ps1"


@functools.cache
def _install_step() -> str:
    pytest.importorskip("yaml")
    from tests._workflow_contexts import step_script

    return step_script("ci.yml", _JOB, _STEP)[1]


def _key_problem(script: str) -> str | None:
    """What is wrong with where ``script`` mints the registry client key, or ``None``."""
    cert_dir = re.search(r"^\s*\$certDir\s*=\s*(.+)$", script, re.MULTILINE)
    if cert_dir is None:
        return "the step no longer assigns $certDir"
    if not cert_dir.group(1).startswith(f'"{_DATA_DIR}\\'):
        return f"the key is minted outside the locked data directory: {cert_dir.group(1)}"
    install = script.find("install-service.ps1")
    if install == -1 or install > cert_dir.start():
        return "the key is minted before install-service.ps1 has locked the data directory"
    if "MEFOR_VALUE_REGISTRY_CLIENT_KEY=$key" not in script:
        return "the service is no longer handed the key minted here"
    moved = script.find("Move-Item -Force -Path $wrapped -Destination $key")
    checked = re.search(r"key_file_problem[^\n]*\n[^\n]*\bthrow\b", script)
    if moved == -1 or checked is None or checked.start() < moved:
        return "the step does not fail on the engine's key-file check of the key it minted"
    return None


def test_the_smoke_mints_the_registry_key_under_the_locked_data_directory() -> None:
    problem = _key_problem(_install_step())
    assert problem is None, (
        f"{_JOB} / {_STEP}: {problem}. Under enforce the service refuses a connection key a broad "
        "group can read (BACKLOG #3402), and the leg runs only in the merge queue."
    )


@pytest.mark.parametrize(
    ("old", "new"),
    [
        # The shape run 39539448967 failed on.
        (
            f'$certDir = "{_DATA_DIR}\\registry-cert"',
            '$certDir = Join-Path $env:RUNNER_TEMP "registry-cert"',
        ),
        (f'$certDir = "{_DATA_DIR}\\', '$certDir = "C:\\mefor\\'),
        ("key_file_problem", "key_file_absent"),
        ('throw "serve would refuse the registry client key', 'Write-Warning "serve would refuse'),
    ],
)
def test_the_key_check_can_fail_on_each_arm(old: str, new: str) -> None:
    """CONTROL: each condition above must be able to fail on the real step text."""
    script = _install_step()
    assert old in script, f"CONTROL FAILED: {old!r} is not in the step, so this arm plants nothing"
    assert _key_problem(script.replace(old, new)) is not None


def test_the_smokes_path_is_the_installers_default_data_directory() -> None:
    """The step names the data directory by its path, so it is the locked one only while the
    installer's default -DataDir is that path and the smoke passes no -DataDir. That the installer
    locks -DataDir is pinned in ``tests/test_service_install_manifest.py``."""
    text = _INSTALLER.read_text(encoding="utf-8")
    assert f'[string]$DataDir = "{_DATA_DIR}"' in text
    assert re.search(r"install-service\.ps1[^\n]*", _install_step()), "the step no longer installs"
    assert not re.search(r"install-service\.ps1[^\n]*-DataDir", _install_step())
