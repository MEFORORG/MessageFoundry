# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""install-usage-statusline.ps1: how it writes a settings file, and how it reads its path arguments.

BACKLOG #7576 and #7577. EVERY PATH HERE IS UNDER ``tmp_path``. The installer writes into a config
root's settings.json, so a test that let it fall through to its own root resolution would wire the
real account this suite runs under. Each call names ``-SettingsPath`` explicitly, pops the
``CLAUDE_CONFIG_DIR`` pin, and passes ``-HomeDir`` inside ``tmp_path``.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from tests._spawn_lock import run_single

ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / "scripts" / "coord" / "install-usage-statusline.ps1"
COLLECT = ROOT / "scripts" / "coord" / "usage-collect.ps1"
TIMEOUT = 60

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="the installer needs pwsh on Windows",
)


def _env() -> dict[str, str]:
    env = os.environ.copy()
    env.pop("CLAUDE_CONFIG_DIR", None)
    return env


def _spawn(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return run_single(
        cmd, capture_output=True, text=True, timeout=TIMEOUT, check=False, env=_env(), cwd=cwd
    )


def _home(tmp_path: Path) -> Path:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    return home


def _install(
    tmp_path: Path, *args: str, cwd: Path, collector: str | None = None
) -> subprocess.CompletedProcess[str]:
    """The documented invocation, ``pwsh -File``."""
    cmd = ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(INSTALL)]
    cmd += ["-HomeDir", str(_home(tmp_path)), "-CollectorPath", collector or str(COLLECT), *args]
    return _spawn(cmd, cwd)


def _install_in_session(
    tmp_path: Path, args: str, *, cwd: Path, location: Path | None = None
) -> subprocess.CompletedProcess[str]:
    """Call the installer with ``&`` inside one pwsh session, the only way to bind an ARRAY to
    ``-SettingsPath`` (``pwsh -File`` refuses a repeated parameter) or to give it a ``$PWD`` that
    differs from the process directory (``location``)."""
    script = f"& '{INSTALL}' -HomeDir '{_home(tmp_path)}' -CollectorPath '{COLLECT}' {args}"
    if location is not None:
        script = f"Set-Location -LiteralPath '{location}'; {script}"
    return _spawn(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", f"{script}; exit $LASTEXITCODE"], cwd
    )


def _root(tmp_path: Path, settings: dict[str, Any] | None = None) -> Path:
    root = tmp_path / "root"
    root.mkdir()
    if settings is not None:
        (root / "settings.json").write_text(json.dumps(settings), encoding="utf-8")
    return root


def _status_line(settings: Path) -> dict[str, Any]:
    sl: dict[str, Any] = json.loads(settings.read_text(encoding="utf-8"))["statusLine"]
    return sl


def _wired_state_dir(settings: Path) -> Path:
    cmd = _status_line(settings)["command"]
    m = re.search(r'-StateDir "([^"]+)"', cmd)
    assert m, cmd
    return Path(m.group(1))


# --- #7576: the write ------------------------------------------------------------------------------


def test_a_rewrite_replaces_the_file_rather_than_truncating_it_in_place(tmp_path: Path) -> None:
    """A LIVE settings.json MUST NEVER BE OBSERVABLE HALF-WRITTEN. Claude Code reads it at session
    start, and a truncated file disables every setting in it. Writing a sibling temporary file and
    renaming it over the target is what makes the replacement whole-or-nothing, and the observable
    trace of that is the FILE IDENTITY: a rename installs a different file, while an in-place rewrite
    (``Set-Content`` truncating the open target) keeps the same one. No temporary file may be left
    behind, and the bytes carry no BOM, which a JSON reader such as ``JSON.parse`` refuses."""
    root = _root(tmp_path, {"theme": "dark"})
    settings = root / "settings.json"
    before = os.stat(settings).st_ino
    proc = _install(tmp_path, "-SettingsPath", str(settings), cwd=tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert os.stat(settings).st_ino != before, "settings.json was rewritten in place"
    assert not settings.read_bytes().startswith(b"\xef\xbb\xbf")
    assert json.loads(settings.read_text(encoding="utf-8"))["theme"] == "dark"
    assert not [p.name for p in root.iterdir() if p.name.endswith(".tmp")]


def test_a_rewrite_keeps_the_existing_key_order(tmp_path: Path) -> None:
    """A GUARD, NOT A REPAIR. #7576 claimed ``ConvertFrom-Json -AsHashtable`` permutes key order; on
    pwsh 7.3 and later it returns an ``OrderedHashtable`` at every level (measured on 7.6.10), so the
    claim does not hold. This pins it, so a parser swap that did permute order would show here."""
    original = {"zeta": 1, "alpha": {"y": 1, "b": 2}, "mid": 3, "aa": 4, "q": 5, "c": 6}
    root = _root(tmp_path, original)
    settings = root / "settings.json"
    proc = _install(tmp_path, "-SettingsPath", str(settings), cwd=tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    after = json.loads(settings.read_text(encoding="utf-8"))
    assert list(after) == [*original, "statusLine"]
    assert list(after["alpha"]) == ["y", "b"]


# --- #7577: the path and argument readings ---------------------------------------------------------


def test_a_bare_settings_filename_names_the_current_directory_as_its_root(tmp_path: Path) -> None:
    """``Split-Path settings.json -Parent`` is the empty string, so the root used to normalise to
    ``$null`` and ``Get-UsageStateDir`` threw a parameter-binding error outside any try."""
    root = _root(tmp_path, {})
    proc = _install(tmp_path, "-SettingsPath", "settings.json", cwd=root)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert _wired_state_dir(root / "settings.json") == root / "mefor-usage"


def test_a_relative_settings_path_resolves_against_the_powershell_location(tmp_path: Path) -> None:
    """``$PWD`` AND THE PROCESS DIRECTORY DIFFER WHEN THE SCRIPT IS CALLED WITH ``&`` after a
    ``Set-Location``, which does not move ``[Environment]::CurrentDirectory``. The file was written
    under ``$PWD`` while its root went through ``GetFullPath`` against the process directory, so the
    wired command published into a directory that is not that root's."""
    root = _root(tmp_path, {})
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    proc = _install_in_session(
        tmp_path, "-SettingsPath 'settings.json'", cwd=elsewhere, location=root
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert _wired_state_dir(root / "settings.json") == root / "mefor-usage"
    assert not (elsewhere / "mefor-usage").exists()


def test_a_settings_path_in_a_missing_directory_stops_the_run_before_any_write(
    tmp_path: Path,
) -> None:
    """ALL OR NOTHING, as the shell-quoting pre-pass already is. A missing parent used to surface
    only inside the write loop, as FAILED for that one target after the others were written."""
    root = _root(tmp_path, {"keep": True})
    good = root / "settings.json"
    missing = tmp_path / "no-such-dir" / "settings.json"
    proc = _install_in_session(tmp_path, f"-SettingsPath @('{good}', '{missing}')", cwd=tmp_path)
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "CANNOT START" in proc.stdout
    assert json.loads(good.read_text(encoding="utf-8")) == {"keep": True}


def test_a_relative_collector_path_is_wired_as_an_absolute_one(tmp_path: Path) -> None:
    """A statusLine runs from the session's working directory, not the installer's, so a relative
    collector path that passed the installer's existence check names nothing when it fires."""
    root = _root(tmp_path, {})
    settings = root / "settings.json"
    proc = _install(
        tmp_path,
        "-SettingsPath",
        str(settings),
        cwd=ROOT,
        collector=os.path.join("scripts", "coord", "usage-collect.ps1"),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert f'-File "{COLLECT}"' in _status_line(settings)["command"]


@pytest.mark.parametrize("interval", ["0", "-5", "999"])
def test_a_refresh_interval_below_the_honoured_minimum_is_refused(
    tmp_path: Path, interval: str
) -> None:
    """Claude Code does not honour an interval under 1000 ms, so writing one would make the
    installer's own ``refreshInterval: <n> ms`` summary line false."""
    root = _root(tmp_path, {"keep": True})
    settings = root / "settings.json"
    proc = _install(
        tmp_path, "-SettingsPath", str(settings), f"-RefreshInterval:{interval}", cwd=tmp_path
    )
    assert proc.returncode != 0, proc.stdout + proc.stderr
    assert json.loads(settings.read_text(encoding="utf-8")) == {"keep": True}


def test_a_non_numeric_refresh_interval_on_our_own_status_line_is_rewired(tmp_path: Path) -> None:
    """``[int]'abc'`` threw inside the try, so the root counted FAILED on every run and a re-install,
    the documented repair, could never repair it."""
    root = _root(tmp_path, {})
    settings = root / "settings.json"
    first = _install(tmp_path, "-SettingsPath", str(settings), cwd=tmp_path)
    assert first.returncode == 0, first.stdout + first.stderr
    doc = json.loads(settings.read_text(encoding="utf-8"))
    doc["statusLine"]["refreshInterval"] = "abc"
    settings.write_text(json.dumps(doc), encoding="utf-8")
    proc = _install(tmp_path, "-SettingsPath", str(settings), cwd=tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "REWIRED" in proc.stdout
    assert _status_line(settings)["refreshInterval"] == 10000
