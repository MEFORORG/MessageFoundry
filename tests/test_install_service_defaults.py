# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""install-service.ps1's defaults no longer point into the checkout (vault BACKLOG #2626 step 1).

The installer used to default the engine to ``<repo>\\.venv``, the config to ``<repo>\\samples\\config``
and the working directory to the repo, and registered no ``--service-config``. Now the engine
defaults to an admin-only install root it checks, ``-Config`` has no default, and the settings file
and project root are registered by absolute path.

What is static here reads the script body, which no test runs: it registers a service. What is
behaviour runs the script's own helper functions, extracted by AST, through ``pwsh``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

import messagefoundry.service as svc
from tests.test_service_install_manifest import _extract, _ok, _psq

_SCRIPT = svc.install_script_path()

pytestmark = pytest.mark.skipif(
    _SCRIPT is None,
    reason="install-service.ps1 not locatable (off-repo / non-editable install)",
)


def _text() -> str:
    assert _SCRIPT is not None
    return _SCRIPT.read_text(encoding="utf-8")


def test_no_default_points_into_the_checkout() -> None:
    text = _text()
    assert '".venv\\Scripts\\messagefoundry.exe"' not in text
    assert 'Join-Path $RepoRoot "samples\\config"' not in text
    assert "pip install -e" not in text
    assert "Invoke-Nssm set $ServiceName AppDirectory $AppDirectory" in text
    assert "AppDirectory $RepoRoot" not in text


def test_the_default_engine_is_the_admin_only_install_root() -> None:
    text = _text()
    assert re.search(
        r'^\$DefaultInstallRoot = Join-Path \$env:ProgramFiles "MessageFoundry\\engine"\r?$',
        text,
        re.M,
    )
    assert (
        "if ($UsesDefaultInstall) { $AppExe = Join-Path $DefaultInstallRoot "
        '"Scripts\\messagefoundry.exe" }'
    ) in text


def test_config_has_no_default_and_its_absence_is_refused() -> None:
    text = _text()
    refusal = text.index("if (-not $Config) {")
    assert "throw" in text[refusal : refusal + 300]
    # Before the first thing that acts: the NSSM copy.
    assert refusal < text.index("$NssmPath = Resolve-Nssm")


def test_only_the_default_install_root_is_checked_for_broad_write() -> None:
    """The check on a passed -AppExe waits on an owner ruling, so the one call sits under the
    default-install condition and refuses there."""
    text = _text()
    calls = [m.start() for m in re.finditer(r"Get-NssmHomeProblem -File \$AppExe", text)]
    assert len(calls) == 1, calls
    guard = text.rindex("if ($UsesDefaultInstall) {", 0, calls[0])
    assert text[guard : calls[0]].count("}") == 0, (
        "the call is not inside the default-install block"
    )
    assert "throw" in text[calls[0] : calls[0] + 500]


def test_the_settings_file_and_project_root_are_registered_by_absolute_path() -> None:
    text = _text()
    params = text.index("$AppParams = ")
    service_config = text.index(
        'if ($ServiceConfig) { $AppParams += " --service-config `"$ServiceConfig`"" }'
    )
    project_root = text.index(
        'if ($ProjectRoot) { $AppParams += " --project-root `"$ProjectRoot`"" }'
    )
    assert params < service_config < project_root
    # Both are normalised with the other paths (tests/test_service_install_manifest.py holds when).
    assert "$ServiceConfig = Resolve-AbsolutePath $ServiceConfig" in text
    assert "$ProjectRoot = Resolve-AbsolutePath $ProjectRoot" in text


def test_lock_config_dir_locks_the_value_folder_too() -> None:
    text = _text()
    block = text.index("if ($LockConfigDir) {")
    folder = text.index('$ValueFolder = Join-Path $ValuesAnchor "environments"')
    added = text.index("$LockPaths += $ValueFolder")
    lock = text.index("Set-SecureConfigAcl -Path $LockPath -Account $ServiceAccount")
    assert block < folder < added < lock


def test_the_default_settings_file_is_the_one_serve_would_read(tmp_path: Path) -> None:
    assert _SCRIPT is not None
    with_file = tmp_path / "with"
    with_file.mkdir()
    (with_file / "messagefoundry.toml").write_text("", encoding="utf-8")
    without = tmp_path / "without"
    without.mkdir()
    folder_named_so = tmp_path / "folder"
    (folder_named_so / "messagefoundry.toml").mkdir(parents=True)
    body = (
        "  [pscustomobject]@{\n"
        f"    with = (Get-DefaultServiceConfig -Anchor {_psq(str(with_file))})\n"
        f"    without = (Get-DefaultServiceConfig -Anchor {_psq(str(without))})\n"
        f"    folder = (Get-DefaultServiceConfig -Anchor {_psq(str(folder_named_so))})\n"
        "  } | ConvertTo-Json -Compress\n"
    )
    got = json.loads(
        _ok(_extract(_SCRIPT, ["Get-DefaultServiceConfig"], body), tmp_path)
        .strip()
        .splitlines()[-1]
    )
    assert got == {
        "with": str(with_file / "messagefoundry.toml"),
        "without": "",
        "folder": "",
    }


def test_the_settings_file_and_the_value_folder_share_one_anchor() -> None:
    """Both resolve under -ProjectRoot, else the working directory, as `serve` resolves them, and
    the installer works that anchor out once."""
    text = _text()
    anchor = text.index("$ValuesAnchor = if ($ProjectRoot) { $ProjectRoot } else { $AppDirectory }")
    assert anchor < text.index("Get-DefaultServiceConfig -Anchor $ValuesAnchor")
    assert anchor < text.index('$ValueFolder = Join-Path $ValuesAnchor "environments"')
