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
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

import messagefoundry.service as svc
from messagefoundry.tray.config import _split_command_line
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
    listed = [m.start() for m in re.finditer(r"\$installFiles = @\(\$AppExe, \$PythonExe,", text)]
    assert len(listed) == 1, listed
    guard = text.rindex("if ($UsesDefaultInstall) {", 0, listed[0])
    assert text[guard : listed[0]].count("}") == 0, (
        "the list is not inside the default-install block"
    )
    # The launcher, the interpreter the service runs and the package it imports.
    assert "Lib\\site-packages\\messagefoundry\\__init__.py" in text[listed[0] : listed[0] + 200]
    assert "Get-NssmHomeProblem -File $_" in text[listed[0] : listed[0] + 500]
    assert "throw" in text[listed[0] : listed[0] + 700]


def test_python_exe_alone_needs_no_launcher() -> None:
    """With -PythonExe and no -AppExe there is no launcher to normalise, and an empty one would
    fail Resolve-AbsolutePath's mandatory parameter."""
    assert "elseif ($AppExe) { $AppExe = Resolve-AbsolutePath $AppExe }" in _text()


def test_a_drive_root_project_root_keeps_its_closing_quote(tmp_path: Path) -> None:
    """``D:\\`` quoted as is would end in ``\\"``, which the command-line parser reads as a quote."""
    assert _SCRIPT is not None
    assert (
        'if ($ProjectRoot) { $AppParams += " --project-root $(Format-QuotedPath $ProjectRoot)" }'
        in (_text())
    )
    body = (
        "  [pscustomobject]@{\n"
        "    root = (Format-QuotedPath 'D:\\')\n"
        "    folder = (Format-QuotedPath 'D:\\hl7')\n"
        "  } | ConvertTo-Json -Compress\n"
    )
    got = json.loads(
        _ok(_extract(_SCRIPT, ["Assert-NoNssmExpansion", "Format-QuotedPath"], body), tmp_path)
        .strip()
        .splitlines()[-1]
    )
    assert got == {"root": '"D:\\\\"', "folder": '"D:\\hl7"'}


def test_the_settings_file_and_project_root_are_registered_by_absolute_path() -> None:
    text = _text()
    params = text.index("$AppParams = ")
    service_config = text.index(
        'if ($ServiceConfig) { $AppParams += " --service-config $(Format-QuotedPath $ServiceConfig)" }'
    )
    project_root = text.index(
        'if ($ProjectRoot) { $AppParams += " --project-root $(Format-QuotedPath $ProjectRoot)" }'
    )
    assert params < service_config < project_root
    # Both are normalised with the other paths (tests/test_service_install_manifest.py holds when).
    assert "$ServiceConfig = Resolve-AbsolutePath $ServiceConfig" in text
    assert "$ProjectRoot = Resolve-AbsolutePath $ProjectRoot" in text


def test_lock_config_dir_locks_each_start_folder_it_may() -> None:
    """``-LockConfigDir`` locks the value folder and the settings file's folder with the config
    directory, each only when Get-LockPathProblem clears it. The settings folder must also not sit
    in the checkout. Whatever stays unlocked is named in one warning, with both refusal criteria."""
    text = _text()
    folder = text.index('$ValueFolder = Join-Path $ValuesAnchor "environments"')
    settings = text.index(
        "Path = (Split-Path -Parent $ServiceConfig); NotWithin = @($RepoRoot); "
        "OnlyFolders = @($Config, $ValueFolder)"
    )
    block = text.index("if ($LockConfigDir) {\n    $LockPaths = @($Config)")
    check = text.index(
        "-NotWithin (@($folder.NotWithin) + $LockNotWithin) -OnlyFolders $folder.OnlyFolders"
    )
    cleared = text.index("else { $LockPaths += $folder.Path }")
    lock = text.index("Set-SecureConfigAcl -Path $LockPath -Account $ServiceAccount")
    warning = text.index('Write-Warning ("This installer did not lock "')
    assert folder < settings < block < check < cleared < lock < warning
    # The warning names the owner arm as well as a write grant, and a section that exists.
    said = text[warning : warning + 700]
    assert "owner is neither the run-as account nor an administrator" in said
    assert "'Lock down the config directory (CONFIG-2)'" in said
    assert "'Restrict the config directory'" not in text


def test_lock_config_dir_refuses_a_config_it_must_not_lock_before_anything_acts() -> None:
    text = _text()
    check = text.index(
        "$configLockProblem = Get-LockPathProblem -Path $Config -Holds $LockKeepOut "
        "-NotWithin $LockNotWithin"
    )
    assert "throw" in text[check : check + 300]
    assert check < text.index("$NssmPath = Resolve-Nssm")
    keep = text.index("$LockKeepOut = @(")
    listed = text[keep : text.index("$LockNotWithin = @($env:SystemRoot)", keep)]
    for name in (
        "$DataDir",
        "$NssmDir",
        "$RepoRoot",
        "$AppDirectory",
        "$DbPath",
        "$PythonExe",
        "$env:ProgramFiles",
        "${env:ProgramFiles(x86)}",
        "$env:ProgramData",
        "$env:ProgramW6432",
        "Split-Path -Parent $env:PUBLIC",
        "Split-Path -Parent $env:USERPROFILE",
    ):
        assert name in listed, name


def _lock_problems(tmp_path: Path, cases: dict[str, str]) -> dict[str, str]:
    assert _SCRIPT is not None
    body = (
        "  [pscustomobject]@{\n"
        + "".join(f"    {key} = ({call})\n" for key, call in cases.items())
        + "  } | ConvertTo-Json -Compress\n"
    )
    out = _ok(_extract(_SCRIPT, ["Get-LockPathProblem"], body), tmp_path)
    got: dict[str, str] = json.loads(out.strip().splitlines()[-1])
    return got


@pytest.mark.skipif(sys.platform != "win32", reason="Windows paths and junctions")
def test_get_lock_path_problem_refuses_a_root_a_junction_a_holder_and_the_checkout(
    tmp_path: Path,
) -> None:
    dedicated = tmp_path / "hl7"
    (dedicated / "config").mkdir(parents=True)
    data = tmp_path / "data"
    data.mkdir()
    repo = tmp_path / "repo"
    (repo / "settings").mkdir(parents=True)
    neighbour = tmp_path / "repo2"
    neighbour.mkdir()
    junction = tmp_path / "junction"
    made = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(dedicated)], capture_output=True
    )
    assert made.returncode == 0, made
    q = _psq
    got = _lock_problems(
        tmp_path,
        {
            "drive": "Get-LockPathProblem -Path 'D:\\'",
            "system": "Get-LockPathProblem -Path 'C:\\'",
            "junction": f"Get-LockPathProblem -Path {q(str(junction))}",
            "holder": f"Get-LockPathProblem -Path {q(str(tmp_path))} -Holds @({q(str(data))})",
            "same": f"Get-LockPathProblem -Path {q(str(data))} -Holds @({q(str(data))})",
            "inside": (
                f"Get-LockPathProblem -Path {q(str(repo / 'settings'))} -NotWithin @({q(str(repo))})"
            ),
            "neighbour": (
                f"Get-LockPathProblem -Path {q(str(neighbour))} -Holds @({q(str(repo))}) "
                f"-NotWithin @({q(str(repo))})"
            ),
            "crowded": (
                f"Get-LockPathProblem -Path {q(str(dedicated))} "
                f"-OnlyFolders @({q(str(dedicated / 'other'))})"
            ),
            "own": (
                f"Get-LockPathProblem -Path {q(str(dedicated))} "
                f"-OnlyFolders @({q(str(dedicated / 'CONFIG'))})"
            ),
            "dedicated": (
                f"Get-LockPathProblem -Path {q(str(dedicated))} -Holds @({q(str(data))}, "
                f"{q(str(repo))}, '') -NotWithin @({q(str(repo))})"
            ),
            "missing": f"Get-LockPathProblem -Path {q(str(tmp_path / 'absent'))}",
        },
    )
    assert got["drive"] == got["system"] == "it is the root of a volume"
    assert got["junction"] == "it is a junction, a link or a mounted volume"
    assert got["holder"] == f"it holds '{data}'"
    assert got["same"] == f"it holds '{data}'"
    assert got["inside"] == f"it is inside '{repo}'"
    assert got["neighbour"] == ""
    assert got["dedicated"] == ""
    assert got["crowded"] == "it holds other folders: config"
    assert got["own"] == ""
    # Unread, a path cannot be shown not to be a junction, so it is not locked.
    assert got["missing"] == "it does not exist or could not be read"


def test_a_path_with_a_double_quote_and_a_bad_listen_host_are_refused_before_anything_acts(
    tmp_path: Path,
) -> None:
    """A double quote would end a quoted path early, and an unquoted host with a space would add
    arguments: either way a later ``--host 0.0.0.0`` could override the loopback default."""
    assert _SCRIPT is not None
    text = _text()
    first_act = text.index("$NssmPath = Resolve-Nssm")
    assert text.index("$AppParams = ") < first_act
    assert text.index("if (-not (Test-ListenHost $ListenHost)) {") < first_act
    body = (
        "  $quote = try { Format-QuotedPath 'D:\\x\" --host 0.0.0.0 \"' } catch { 'refused' }\n"
        "  $percent = try { Format-QuotedPath 'D:\\%TEMP%\\cfg' } catch { $_.Exception.Message }\n"
        "  [pscustomobject]@{\n"
        "    quote = $quote\n"
        "    percent = $percent\n"
        "    good = @('127.0.0.1', '::1', 'fe80::1', 'fe80::1%12', '0.0.0.0', 'localhost', "
        "'engine-1.example.org', '3par-mgmt', '10.0.0.1x', '1e5' |"
        " ForEach-Object { Test-ListenHost $_ })\n"
        "    bad = @('127.0.0.1 --host 0.0.0.0', '\"127.0.0.1\"', '', '-x', 'a..b', 'a_b', '0', "
        "'1.2', '0x0', '127.0.0.010', 'a.1', '::1%PATH%', 'fe80::1%TEMP%', 'host%1' |"
        " ForEach-Object { Test-ListenHost $_ })\n"
        "  } | ConvertTo-Json -Compress\n"
    )
    got = json.loads(
        _ok(
            _extract(
                _SCRIPT, ["Assert-NoNssmExpansion", "Format-QuotedPath", "Test-ListenHost"], body
            ),
            tmp_path,
        )
        .strip()
        .splitlines()[-1]
    )
    assert got == {
        "quote": "refused",
        "percent": "A path nssm stores for the service cannot contain '%': D:\\%TEMP%\\cfg",
        # '10.0.0.1x' and '1e5' are host names: no resolver reads them as a number, so they do
        # not widen the bind, and a name that does not resolve fails at start.
        "good": [True] * 10,
        # nssm expands %NAME% at start, and PowerShell 7's IPAddress.TryParse takes a named zone.
        "bad": [False] * 14,
    }


def test_a_legacy_escape_doubles_trailing_backslashes_only_where_the_host_adds_quotes(
    tmp_path: Path,
) -> None:
    """A legacy host quotes an argument only when it holds white space. Doubling the trailing
    backslash of one it does not quote would change the path nssm stores."""
    assert _SCRIPT is not None
    body = (
        "  [pscustomobject]@{\n"
        "    bare = (ConvertTo-NativeArgument 'C:\\data\\' -Legacy)\n"
        "    spaced = (ConvertTo-NativeArgument 'C:\\my data\\' -Legacy)\n"
        "    quoted = (ConvertTo-NativeArgument 'a \"b\\\\\" c' -Legacy)\n"
        "    standard = (ConvertTo-NativeArgument 'a \"b\" c\\')\n"
        "  } | ConvertTo-Json -Compress\n"
    )
    got = json.loads(
        _ok(_extract(_SCRIPT, ["ConvertTo-NativeArgument"], body), tmp_path)
        .strip()
        .splitlines()[-1]
    )
    assert got == {
        "bare": "C:\\data\\",
        "spaced": "C:\\my data\\\\",
        "quoted": 'a \\"b\\\\\\\\\\" c',
        "standard": 'a "b" c\\',
    }


def _run_on(host: str, script: str, tmp_path: Path) -> str:
    f = tmp_path / f"harness-{uuid.uuid4().hex}.ps1"
    f.write_text(script, encoding="utf-8")
    r = subprocess.run(
        [host, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(f)],
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert r.returncode == 0, f"{host} harness failed:\n{(r.stderr + r.stdout)[:2000]}"
    return r.stdout


def _app_params_lines() -> str:
    """The three lines that build $AppParams, as the script has them."""
    text = _text()
    lines = [
        line
        for line in text.splitlines()
        if line.startswith("$AppParams = ")
        or line.startswith("if ($ServiceConfig) { $AppParams += ")
        or line.startswith("if ($ProjectRoot) { $AppParams += ")
    ]
    assert len(lines) == 3, lines
    return "\n".join(lines)


@pytest.mark.skipif(
    sys.platform != "win32", reason="the service's command line is parsed on Windows"
)
@pytest.mark.parametrize("host", ["pwsh", "powershell"])
def test_each_path_reaches_the_service_whole_on_each_host(host: str, tmp_path: Path) -> None:
    """The registered AppParameters, handed to a native program the way the script hands it to
    nssm, then split as the service's command line is split. Windows PowerShell 5.1 strips the
    quotes from an argument unless they are escaped, so a path with a space came apart there.

    The raw arm is the positive control: on a legacy host the unescaped string does NOT arrive
    whole, so the instrument can see the defect the escape removes."""
    if not shutil.which(host):
        pytest.skip(f"SKIP (nothing run): {host} not on PATH")
    assert _SCRIPT is not None
    text = _text()
    assert "Invoke-Nssm set $ServiceName AppParameters $AppParams" in text
    invoke = text.index("function Invoke-Nssm {")
    assert "ConvertTo-NativeArgument" in text[invoke : text.index("\n}\n", invoke)]
    paths = {
        "--config": "D:\\hl7 cfg\\config",
        "--db": "C:\\Mefor Data\\messagefoundry.db",
        "--service-config": "D:\\hl7 cfg\\messagefoundry.toml",
        "--project-root": "D:\\",
    }
    echo = tmp_path / "echo.py"
    echo.write_text("import sys, json; print(json.dumps(sys.argv[1]))\n", encoding="utf-8")
    body = (
        "  $EngineInterpreterOptions = '-I -X disable-remote-debug'\n"
        f"  $Config = {_psq(paths['--config'])}\n"
        f"  $DbPath = {_psq(paths['--db'])}\n"
        f"  $ServiceConfig = {_psq(paths['--service-config'])}\n"
        f"  $ProjectRoot = {_psq(paths['--project-root'])}\n"
        "  $ListenHost = '127.0.0.1'; $Port = 8765; $LogLevel = 'INFO'; $Environment = 'prod'\n"
        + _app_params_lines()
        + "\n"
        # Invoke-Nssm runs $NssmPath, so the echo stands in for nssm.exe.
        f"  $NssmPath = {_psq(sys.executable)}\n"
        f"  $echo = {_psq(str(echo))}\n"
        "  $legacy = Test-LegacyNativeArgumentPassing\n"
        "  $sent = Invoke-Nssm $echo $AppParams\n"
        "  $raw = if ($legacy) { & $NssmPath $echo $AppParams | ConvertFrom-Json } else { $null }\n"
        "  [pscustomobject]@{ legacy = $legacy; built = $AppParams; sent = ($sent | ConvertFrom-Json);"
        " raw = $raw } | ConvertTo-Json -Compress\n"
    )
    script = _extract(
        _SCRIPT,
        [
            "Assert-NoNssmExpansion",
            "Format-QuotedPath",
            "Test-LegacyNativeArgumentPassing",
            "ConvertTo-NativeArgument",
            "Invoke-Nssm",
        ],
        body,
    )
    got = json.loads(_run_on(host, script, tmp_path).strip().splitlines()[-1])
    assert got["sent"] == got["built"], got
    if host == "powershell":
        assert got["legacy"] is True
        assert got["raw"] != got["built"], "the positive control: 5.1 strips unescaped quotes"
    # Split as CommandLineToArgvW splits the service's command line; tests/test_tray_config.py
    # checks this splitter against that call.
    argv = _split_command_line(got["sent"])
    for flag, path in paths.items():
        assert argv[argv.index(flag) + 1] == path, (flag, argv)
    assert argv[argv.index("--host") + 1] == "127.0.0.1"
    assert argv.count("--host") == 1


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


def test_the_stored_arguments_are_read_back_unexpanded_and_a_mismatch_disables_the_service() -> (
    None
):
    """The escaping Invoke-Nssm applies is a guess about the host. The registry value nssm wrote
    is the answer, read without expanding %NAME%, and a mismatch leaves the service Disabled."""
    text = _text()
    stored = text.index("Invoke-Nssm set $ServiceName AppParameters $AppParams")
    read = text.index(
        '"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$ServiceName\\Parameters"', stored
    )
    assert (
        "GetValue('AppParameters', $null, 'DoNotExpandEnvironmentNames')" in text[read : read + 300]
    )
    compare = text.index("if ($storedParams -cne $AppParams) {", read)
    disable = text.index("Disable-RefusedService -ServiceName $ServiceName", compare)
    refusal = text.index("throw", compare)
    assert disable < refusal
    # The advice names a newer PowerShell only where this host is the legacy kind it would fix.
    assert text.index("if (Test-LegacyNativeArgumentPassing)", compare) < refusal
    # Before anything else is set on the service.
    assert compare < text.index("Invoke-Nssm set $ServiceName AppDirectory $AppDirectory")


def test_a_refusal_reports_whether_the_service_was_disabled(tmp_path: Path) -> None:
    """The refusal used to say the service "was set to Disabled" even when that call failed
    silently. Now it reports what happened, and a failure tells the operator to do it by hand."""
    assert _SCRIPT is not None
    body = (
        "  function Set-Service { param($Name, $StartupType, $ErrorAction)\n"
        "    if ($Name -eq 'Gone') { throw 'no such service' } }\n"
        "  [pscustomobject]@{\n"
        "    done = (Disable-RefusedService -ServiceName 'Svc' -Consequence 'it cannot start')\n"
        "    failed = (Disable-RefusedService -ServiceName 'Gone' -Consequence 'it cannot start')\n"
        "  } | ConvertTo-Json -Compress\n"
    )
    got = json.loads(
        _ok(_extract(_SCRIPT, ["Disable-RefusedService"], body), tmp_path).strip().splitlines()[-1]
    )
    assert got["done"] == "'Svc' was set to Disabled so it cannot start."
    assert got["failed"].startswith(
        "WARNING: 'Gone' could NOT be set to Disabled (no such service)"
    )
    assert "Set-Service -Name 'Gone' -StartupType Disabled" in got["failed"]


def test_a_path_nssm_expands_is_refused_with_percent_before_anything_acts() -> None:
    """nssm expands %NAME% at start in the interpreter path, the working directory and the log
    paths under -DataDir, as it does in the arguments."""
    text = _text()
    check = text.index(
        "foreach ($stored in @($PythonExe, $AppDirectory, $DataDir)) { Assert-NoNssmExpansion $stored }"
    )
    assert text.index("$PythonExe = Get-EngineInterpreter") < check
    assert check < text.index("$NssmPath = Resolve-Nssm")
