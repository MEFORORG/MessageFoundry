# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The Windows service smoke keeps its connection key where ``enforce`` accepts it (BACKLOG #3402).

The samples graph deploys ``OB_IMMUNIZATION_REGISTRY``, a SOAP outbound with a client key, so the
smoke mints a throwaway pair for it. ``enforce`` refuses a connection's key file that a broad group
can read. The smoke used to mint the pair under ``RUNNER_TEMP``, which grants ``BUILTIN\\Users``
read, and every leg's service then refused to start (CI run 39539448967). The pair is now created
in the data directory ``install-service.ps1`` locks, and the step runs the engine's own check on
the key.

``windows-service-smoke`` runs on a schedule, on dispatch and in the merge queue; a pull request
skips it. So these read the workflow text and fail at the pull request instead. They show where the
step mints the key and that it checks it. They do not show the leg is green: its own result is that
reading. The step's check program is run, against a key in a locked data directory and against an
open one, in ``tests/test_service_install_manifest.py``, which an engine change also runs.
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

#: The step's lines this guard pins, in order, each matched as a whole line. The check program is
#: captured so the engine-leg test can run it.
_CERT_DIR = f'$certDir = "{_DATA_DIR}\\registry-cert"'
_KEY = '$key  = Join-Path $certDir "client.key"'
_MOVE = "Move-Item -Force -Path $wrapped -Destination $key"
_CHECK = re.compile(r'^cmd /c "python -c ""(?P<program>[^"]+)"" ""\$key"" 2>&1"$')
_REFUSED = "if ($keyChecked -eq 3) { throw \"serve would refuse the registry client key '$key'\" }"
_FAILED = "if ($keyChecked -ne 0) { throw \"the key-file check on '$key' did not run"
#: The exit code the step's check program returns for a refused key.
REFUSED_EXIT = 3


@functools.cache
def install_step() -> str:
    """The step's run script, without its comment lines. Cached: each read parses all of ci.yml."""
    pytest.importorskip("yaml")
    from tests._workflow_contexts import step_script

    return step_script("ci.yml", _JOB, _STEP)[1]


def check_program(script: str) -> str | None:
    """The Python program the step runs on the key, or ``None`` when no line runs one on ``$key``."""
    lines = [line.strip() for line in script.splitlines()]
    found = [m for line in lines if (m := _CHECK.match(line))]
    return found[0].group("program") if len(found) == 1 else None


def _key_problem(script: str) -> str | None:
    """What is wrong with where ``script`` mints the registry client key, or ``None``."""
    lines = [line.strip() for line in script.splitlines()]

    def at(text: str) -> int:
        hits = [n for n, line in enumerate(lines) if line == text or line.startswith(text)]
        return hits[0] if len(hits) == 1 else -1

    if sum(line.startswith("$certDir =") for line in lines) != 1 or at(_CERT_DIR) == -1:
        return f"the key directory is not exactly {_CERT_DIR}"
    if sum(line.startswith("$key ") for line in lines) != 1 or at(_KEY) == -1:
        return f"the key is not exactly {_KEY}"
    installs = [n for n, line in enumerate(lines) if "install-service.ps1" in line]
    if not installs or installs[0] > at(_CERT_DIR):
        return "the key is minted before install-service.ps1 has locked the data directory"
    if "DataDir" in script:
        return "the step names a DataDir, so the locked directory may not be the one minted into"
    if "MEFOR_VALUE_REGISTRY_CLIENT_KEY=$key" not in script:
        return "the service is no longer handed the key minted here"
    program = check_program(script)
    checked = next((n for n, line in enumerate(lines) if _CHECK.match(line)), -1)
    if program is None or "key_file_problem" not in program or at(_MOVE) == -1:
        return "the step does not run the engine's key-file check on the key it minted"
    if f"sys.exit({REFUSED_EXIT} if r else 0)" not in program:
        return f"the check program does not exit {REFUSED_EXIT} on a refusal"
    if not (at(_MOVE) < checked and lines[checked + 1] == "$keyChecked = $LASTEXITCODE"):
        return "the check does not run after the key is final, or its exit code is not kept"
    if at(_REFUSED) != checked + 2 or at(_FAILED) != checked + 3:
        return "a refused key, or a check that did not run, does not fail the step"
    return None


def test_the_smoke_mints_the_registry_key_under_the_locked_data_directory() -> None:
    problem = _key_problem(install_step())
    assert problem is None, (
        f"{_JOB} / {_STEP}: {problem}. Under enforce the service refuses a connection key a broad "
        "group can read (BACKLOG #3402), and a pull request skips this leg."
    )


@pytest.mark.parametrize(
    ("old", "new"),
    [
        # The shape run 39539448967 failed on.
        (_CERT_DIR, '$certDir = Join-Path $env:RUNNER_TEMP "registry-cert"'),
        (_KEY, '$key  = Join-Path $env:RUNNER_TEMP "client.key"'),
        (_CERT_DIR, f"{_CERT_DIR}\n$certDir = Join-Path $env:RUNNER_TEMP 'x'"),
        ("install-service.ps1", "install-other.ps1"),
        ("-LockConfigDir", "-DataDir D:\\mefor -LockConfigDir"),
        ("MEFOR_VALUE_REGISTRY_CLIENT_KEY=$key", "MEFOR_VALUE_REGISTRY_CLIENT_KEY=$cert"),
        ("key_file_problem as check", "key_file_absent as check"),
        ('""$key"" 2>&1"', '""$cert"" 2>&1"'),
        (_MOVE, "Copy-Item -Path $wrapped -Destination $key"),
        ("sys.exit(3 if r else 0)", "sys.exit(0)"),
        ("$keyChecked = $LASTEXITCODE", "$keyChecked = 0"),
        ("($keyChecked -eq 3) { throw", "($keyChecked -eq 3) { Write-Warning"),
        ("($keyChecked -ne 0) { throw", "($keyChecked -eq 0) { throw"),
    ],
)
def test_the_key_check_can_fail_on_each_arm(old: str, new: str) -> None:
    """CONTROL: at least one planted regression per condition above, on the real step text."""
    script = install_step()
    assert old in script, f"CONTROL FAILED: {old!r} is not in the step, so this arm plants nothing"
    assert _key_problem(script.replace(old, new)) is not None


def test_the_smokes_path_is_the_installers_default_data_directory() -> None:
    """The step names the data directory by its path, so it is the locked one only while the
    installer's default -DataDir is that path; the step naming no DataDir is checked above. That
    the installer locks -DataDir is pinned in ``tests/test_service_install_manifest.py``."""
    assert f'[string]$DataDir = "{_DATA_DIR}"' in _INSTALLER.read_text(encoding="utf-8")
