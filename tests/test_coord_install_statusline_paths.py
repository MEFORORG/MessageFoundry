# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""install-usage-statusline.ps1: how it writes a settings file, and how it reads its path arguments.

BACKLOG #7576 and #7577. EVERY PATH HERE IS UNDER ``tmp_path``. The installer writes into a config
root's settings.json, so a test that let it fall through to its own root resolution would wire the
real account this suite runs under. Each call pops the ``CLAUDE_CONFIG_DIR`` pin and passes a
``-HomeDir`` inside ``tmp_path``; all but the relative ``-HomeDir`` test also name ``-SettingsPath``,
and that one runs with both its ``$PWD`` and its process directory inside ``tmp_path``.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import string
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


def _env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = os.environ.copy()
    env.pop("CLAUDE_CONFIG_DIR", None)
    env.pop("MEFOR_TEST_STATUSLINE_SWAP_FAULT", None)
    env.update(extra or {})
    return env


def _q(path: Path | str) -> str:
    """A PowerShell single-quoted literal: an apostrophe in a path is doubled, not a parse error."""
    return "'" + str(path).replace("'", "''") + "'"


def _spawn(
    cmd: list[str], cwd: Path, extra_env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return run_single(
        cmd,
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
        env=_env(extra_env),
        cwd=cwd,
    )


def _home(tmp_path: Path) -> Path:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    return home


def _install(
    tmp_path: Path,
    *args: str,
    cwd: Path,
    collector: str | None = None,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """The documented invocation, ``pwsh -File``."""
    cmd = ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(INSTALL)]
    cmd += ["-HomeDir", str(_home(tmp_path)), "-CollectorPath", collector or str(COLLECT), *args]
    return _spawn(cmd, cwd, extra_env)


def _free_drive() -> str:
    """A drive letter nothing is mapped to, found at run time; skips the test when all are taken."""
    free = next(
        (d for d in reversed(string.ascii_uppercase) if not os.path.exists(f"{d}:\\")), None
    )
    if free is None:
        pytest.skip("every drive letter is in use, so no gone drive can be named")
    return free


def _install_in_session(
    tmp_path: Path, args: str, *, cwd: Path, location: Path | None = None
) -> subprocess.CompletedProcess[str]:
    """Call the installer with ``&`` inside one pwsh session, the only way to bind an ARRAY to
    ``-SettingsPath`` (``pwsh -File`` refuses a repeated parameter) or to give it a ``$PWD`` that
    differs from the process directory (``location``)."""
    script = f"& {_q(INSTALL)} -HomeDir {_q(_home(tmp_path))} -CollectorPath {_q(COLLECT)} {args}"
    if location is not None:
        script = f"Set-Location -LiteralPath {_q(location)}; {script}"
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


def test_a_settings_path_in_a_missing_directory_stops_the_run_before_any_write(
    tmp_path: Path,
) -> None:
    """ALL OR NOTHING, as the shell-quoting pre-pass already is. A missing parent used to surface
    only inside the write loop, as FAILED for that one target after the others were written."""
    root = _root(tmp_path, {"keep": True})
    good = root / "settings.json"
    missing = tmp_path / "no-such-dir" / "settings.json"
    proc = _install_in_session(
        tmp_path, f"-SettingsPath @({_q(good)}, {_q(missing)})", cwd=tmp_path
    )
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
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "CANNOT START" in proc.stdout
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


def test_a_path_on_a_drive_that_does_not_exist_is_a_usage_error(tmp_path: Path) -> None:
    """An unmapped drive made the resolver throw, uncaught, so the run ended on a raw exception and
    exit 1, which here means "roots were targeted and none reached the desired state"."""
    free = _free_drive()
    proc = _install(tmp_path, "-SettingsPath", f"{free}:\\nope\\settings.json", cwd=tmp_path)
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "cannot be resolved" in proc.stdout


def test_uninstall_reports_a_root_on_a_gone_drive_as_unknown_not_absent(tmp_path: Path) -> None:
    """NOT PRESENT IS A READING, AND NOTHING WAS READ. Test-Path is False for a path on a drive that
    is not there, which Read-Settings turned into an empty document, so the run reported NOT PRESENT
    and exited 0 while the root may still carry a live statusLine."""
    gone = f"{_free_drive()}:\\nope\\settings.json"
    proc = _install(tmp_path, "-Uninstall", "-SettingsPath", gone, cwd=tmp_path)
    assert re.search(r"^\s*UNKNOWN\s+" + re.escape(gone), proc.stdout, re.M), proc.stdout
    assert "NOT PRESENT" not in proc.stdout, proc.stdout
    assert "not present: 0" in proc.stdout and "unknown: 1" in proc.stdout, proc.stdout
    assert proc.returncode == 1, proc.stdout + proc.stderr


def test_status_reports_a_root_on_a_gone_drive_as_unknown(tmp_path: Path) -> None:
    """The publish-path line threw on a missing drive, so the audit ended there on a raw error."""
    gone = f"{_free_drive()}:\\nope\\settings.json"
    proc = _install(tmp_path, "-Status", "-SettingsPath", gone, cwd=tmp_path)
    assert re.search(r"statusLine\s+: UNKNOWN", proc.stdout), proc.stdout + proc.stderr
    assert "Cannot find drive" not in proc.stdout + proc.stderr
    assert "This reads the FILE" in proc.stdout, proc.stdout
    assert proc.returncode == 1, proc.stdout + proc.stderr


# --- #7576: a swap that fails part way -------------------------------------------------------------


def test_a_swap_that_fails_part_way_puts_the_original_back(tmp_path: Path) -> None:
    """NEITHER FILE IS THE ONE OUTCOME THAT MUST NOT HAPPEN. ReplaceFile can fail after it has moved
    settings.json aside; with no backup name and an unconditional temp-file delete, the original was
    gone and the only copy of the new content was deleted after it. The fault seam reproduces that
    swap state, and the run must fail loudly with the original back in place."""
    root = _root(tmp_path, {"keep": True})
    settings = root / "settings.json"
    proc = _install(
        tmp_path,
        "-SettingsPath",
        str(settings),
        cwd=tmp_path,
        extra_env={"MEFOR_TEST_STATUSLINE_SWAP_FAULT": "original-moved-aside"},
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "FAILED" in proc.stdout and "was not updated" in proc.stdout, proc.stdout
    assert json.loads(settings.read_text(encoding="utf-8")) == {"keep": True}
    assert not [p.name for p in root.iterdir() if p.name.endswith((".tmp", ".swap-bak"))]


def test_a_swap_whose_restore_also_fails_keeps_both_copies_and_names_them(tmp_path: Path) -> None:
    """When the original cannot be put back either, the temp file is the new content and the swap
    backup is the old one; both stay, and the FAILED line names each path."""
    root = _root(tmp_path, {"keep": True})
    settings = root / "settings.json"
    proc = _install(
        tmp_path,
        "-SettingsPath",
        str(settings),
        cwd=tmp_path,
        extra_env={"MEFOR_TEST_STATUSLINE_SWAP_FAULT": "original-moved-aside-restore-fails"},
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert not settings.exists()
    (tmp,) = [p for p in root.iterdir() if p.name.endswith(".tmp")]
    (bak,) = [p for p in root.iterdir() if p.name.endswith(".swap-bak")]
    assert "statusLine" in json.loads(tmp.read_text(encoding="utf-8"))
    assert json.loads(bak.read_text(encoding="utf-8")) == {"keep": True}
    flat = " ".join(proc.stdout.split())
    assert "settings.json is MISSING" in flat, proc.stdout
    assert str(tmp) in flat and str(bak) in flat, proc.stdout


def test_a_failed_swap_on_a_root_with_no_settings_keeps_the_new_content(tmp_path: Path) -> None:
    """With no settings.json before the run there is no backup to put back, so the complete temp file
    is the only copy of the new content; it stays, and the FAILED line names it."""
    root = _root(tmp_path)
    settings = root / "settings.json"
    proc = _install(
        tmp_path,
        "-SettingsPath",
        str(settings),
        cwd=tmp_path,
        extra_env={"MEFOR_TEST_STATUSLINE_SWAP_FAULT": "original-moved-aside"},
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert not settings.exists()
    (tmp,) = [p for p in root.iterdir() if p.name.endswith(".tmp")]
    assert "statusLine" in json.loads(tmp.read_text(encoding="utf-8"))
    flat = " ".join(proc.stdout.split())
    assert "settings.json was not created" in flat and str(tmp) in flat, proc.stdout


def test_status_and_uninstall_still_report_on_a_deleted_root(tmp_path: Path) -> None:
    """The missing-directory pre-check guards WRITES. An audit or an uninstall over a list of roots,
    some already deleted, reports each one rather than stopping at the first."""
    gone = tmp_path / "gone" / "settings.json"
    for mode in ("-Status", "-Uninstall"):
        proc = _install(tmp_path, mode, "-SettingsPath", str(gone), cwd=tmp_path)
        assert "CANNOT START" not in proc.stdout, (mode, proc.stdout)
        assert "UNKNOWN" not in proc.stdout, (mode, proc.stdout)
    # On a reachable drive the absence IS what the run read.
    status = _install(tmp_path, "-Status", "-SettingsPath", str(gone), cwd=tmp_path)
    assert re.search(r"publishes to\s+: nothing", status.stdout), status.stdout
    assert status.returncode == 1, status.stdout + status.stderr
    uninstall = _install(tmp_path, "-Uninstall", "-SettingsPath", str(gone), cwd=tmp_path)
    assert re.search(r"^\s*NOT PRESENT\s+", uninstall.stdout, re.M), uninstall.stdout
    assert uninstall.returncode == 0, uninstall.stdout + uninstall.stderr


def test_a_dry_run_uninstall_over_a_gone_drive_does_not_exit_zero(tmp_path: Path) -> None:
    """Exit 0 means every root reached the desired state, and nothing about this one was read."""
    gone = f"{_free_drive()}:\\nope\\settings.json"
    proc = _install(tmp_path, "-Uninstall", "-WhatIf", "-SettingsPath", gone, cwd=tmp_path)
    assert "unknown: 1" in proc.stdout, proc.stdout
    assert proc.returncode == 1, proc.stdout + proc.stderr


def test_a_hard_linked_settings_file_is_written_through_not_cut(tmp_path: Path) -> None:
    """A REPLACE CUTS A HARD LINK: the root would become a standalone copy while the shared file kept
    its old content. A linked file is still written in place, so both names see the statusLine."""
    root = _root(tmp_path, {"shared": True})
    settings = root / "settings.json"
    other = tmp_path / "shared.json"
    os.link(settings, other)
    proc = _install(tmp_path, "-SettingsPath", str(settings), cwd=tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert os.stat(settings).st_ino == os.stat(other).st_ino
    assert "statusLine" in json.loads(other.read_text(encoding="utf-8"))


def test_a_symlinked_settings_file_is_written_through_to_its_target(tmp_path: Path) -> None:
    """A symbolic link is followed, so the link survives and its target gets the statusLine."""
    root = _root(tmp_path)
    target = tmp_path / "real-settings.json"
    target.write_text("{}", encoding="utf-8")
    settings = root / "settings.json"
    try:
        settings.symlink_to(target)
    except OSError:
        pytest.skip("this account cannot create a symbolic link")
    proc = _install(tmp_path, "-SettingsPath", str(settings), cwd=tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert settings.is_symlink()
    assert "statusLine" in json.loads(target.read_text(encoding="utf-8"))


def test_status_flags_a_root_wired_with_a_relative_collector(tmp_path: Path) -> None:
    """A root wired before the fix with a relative collector read ``exists: True`` from a checkout
    and counted healthy, while its statusLine resolves the path from each session's directory."""
    root = _root(tmp_path, {})
    settings = root / "settings.json"
    assert _install(tmp_path, "-SettingsPath", str(settings), cwd=tmp_path).returncode == 0
    doc = json.loads(settings.read_text(encoding="utf-8"))
    rel = os.path.join("scripts", "coord", "usage-collect.ps1")
    doc["statusLine"]["command"] = doc["statusLine"]["command"].replace(str(COLLECT), rel)
    settings.write_text(json.dumps(doc), encoding="utf-8")
    proc = _install(tmp_path, "-Status", "-SettingsPath", str(settings), cwd=ROOT)
    assert "RELATIVE" in proc.stdout, proc.stdout
    assert proc.returncode == 1, proc.stdout + proc.stderr


def test_a_relative_home_dir_resolves_against_the_powershell_location(tmp_path: Path) -> None:
    """Rule 5 builds ``<HomeDir>\\.claude`` through ``GetFullPath``, so a relative ``-HomeDir`` after a
    ``Set-Location`` named a root under the process directory instead."""
    home = tmp_path / "h"
    (home / ".claude").mkdir(parents=True)
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / ".claude").mkdir(parents=True)
    script = (
        f"Set-Location -LiteralPath {_q(home)}; "
        f"& {_q(INSTALL)} -HomeDir . -CollectorPath {_q(COLLECT)}; exit $LASTEXITCODE"
    )
    proc = _spawn(["pwsh", "-NoProfile", "-NonInteractive", "-Command", script], elsewhere)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert (home / ".claude" / "settings.json").exists()
    assert not (elsewhere / ".claude" / "settings.json").exists()


def test_status_and_uninstall_ignore_a_low_refresh_interval(tmp_path: Path) -> None:
    """Only an install uses the interval, so a wrapper passing the same arguments to every mode can
    still audit and uninstall."""
    root = _root(tmp_path, {})
    settings = root / "settings.json"
    for mode in ("-Status", "-Uninstall"):
        proc = _install(
            tmp_path, mode, "-SettingsPath", str(settings), "-RefreshInterval:500", cwd=tmp_path
        )
        assert "CANNOT START" not in proc.stdout, (mode, proc.stdout)


def test_a_rewrite_keeps_the_file_acl_and_attributes(tmp_path: Path) -> None:
    """A RENAME OF A FRESH TEMP FILE WIDENS A LOCKED-DOWN FILE: it carries the directory's inherited ACL
    and default attributes. The replace keeps the old file's, as the in-place write did."""
    root = _root(tmp_path, {})
    settings = root / "settings.json"
    lock = (
        f"$p = {_q(settings)}; $a = Get-Acl -LiteralPath $p; $a.SetAccessRuleProtection($true, $false); "
        "$me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name; "
        "$a.SetAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($me, 'FullControl', 'Allow')); "
        "Set-Acl -LiteralPath $p -AclObject $a; (Get-Item -LiteralPath $p).Attributes = 'Hidden'"
    )
    probe = (
        f"$p = {_q(settings)}; $a = Get-Acl -LiteralPath $p; "
        "'{0} {1} {2}' -f $a.AreAccessRulesProtected, $a.Access.Count, "
        "[bool]((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::Hidden)"
    )
    pw = ["pwsh", "-NoProfile", "-NonInteractive", "-Command"]
    assert _spawn([*pw, lock], tmp_path).returncode == 0
    before = _spawn([*pw, probe], tmp_path).stdout.strip()
    assert before == "True 1 True", before
    proc = _install(tmp_path, "-SettingsPath", str(settings), cwd=tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert _spawn([*pw, probe], tmp_path).stdout.strip() == before
