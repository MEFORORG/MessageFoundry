# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""install-usage-statusline.ps1: how it writes a settings file, and how it reads its path arguments.

BACKLOG #7576 and #7577. EVERY PATH WRITTEN HERE IS UNDER ``tmp_path``. The installer writes into a
config root's settings.json, so a test that let it fall through to its own root resolution would
wire the real account this suite runs under. Every call starts from an environment with the
``CLAUDE_CONFIG_DIR`` pin and the swap-fault variables popped, and then names its target, at least
one of these ways: a ``-SettingsPath`` or ``-ConfigDir`` inside ``tmp_path``; a pin set back to a
root inside ``tmp_path`` (the gone-drive ``-HomeDir`` test); or a ``-HomeDir`` inside ``tmp_path``,
or ``.`` with both ``$PWD`` and the process directory inside it (the relative ``-HomeDir`` test). A
``-HomeDir`` that is not inside ``tmp_path`` names a drive that does not exist.
"""

from __future__ import annotations

import ctypes
import json
import os
import re
import shutil
import string
import subprocess
import sys
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
    env.pop("MEFOR_TEST_STATUSLINE_SWAP_FAULT_DIR", None)
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


FAULT_ROOT = "mefor-swap-fault-root"


def _fault(temp: Path, mode: str, root: Path) -> dict[str, str]:
    """The swap fault, fenced the way the seam requires: the root is named by the directory variable,
    its leaf carries the seam's prefix, and it sits inside an explicit TEMP. TEMP as the process spells
    it can differ from ``tmp_path``, which pytest has resolved (an 8.3 ``RUNNER~1`` on a hosted
    runner), so the test names its own temp directory."""
    return {
        "MEFOR_TEST_STATUSLINE_SWAP_FAULT": mode,
        "MEFOR_TEST_STATUSLINE_SWAP_FAULT_DIR": str(root),
        "TEMP": str(temp),
        "TMP": str(temp),
    }


def _free_drive() -> str:
    """A drive letter nothing is mapped to, found at run time; skips the test when all are taken.
    A disconnected persistent mapping still holds its letter in the logical-drive mask, and still
    gets a PowerShell drive, so the mask is consulted as well as the path."""
    mask = 0
    if sys.platform == "win32":
        mask = ctypes.windll.kernel32.GetLogicalDrives()
    free = next(
        (
            d
            for i, d in reversed(list(enumerate(string.ascii_uppercase)))
            if not mask & (1 << i) and not os.path.exists(f"{d}:\\")
        ),
        None,
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


def _root(tmp_path: Path, settings: dict[str, Any] | None = None, *, name: str = "root") -> Path:
    root = tmp_path / name
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


# --- #7576: a swap that fails ----------------------------------------------------------------------


def test_a_failed_move_leaves_the_original_in_place(tmp_path: Path) -> None:
    """NEITHER FILE IS THE ONE OUTCOME THAT MUST NOT HAPPEN. The swap is one rename, so a failed move
    leaves settings.json as it was; the run fails loudly, and its temp file is gone because the
    original is still the live copy."""
    root = _root(tmp_path, {"keep": True}, name=FAULT_ROOT)
    settings = root / "settings.json"
    proc = _install(
        tmp_path,
        "-SettingsPath",
        str(settings),
        cwd=tmp_path,
        extra_env=_fault(tmp_path, "move-fails", root),
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "FAILED" in proc.stdout and "was not updated" in proc.stdout, proc.stdout
    assert json.loads(settings.read_text(encoding="utf-8")) == {"keep": True}
    assert not [p.name for p in root.iterdir() if p.name.endswith(".tmp")]


def test_a_failed_move_after_a_concurrent_delete_keeps_the_new_content_and_names_it(
    tmp_path: Path,
) -> None:
    """A concurrent deleter can take settings.json away, which the move itself never does. The temp
    file is then the only copy of the new content and the pre-run backup the only copy of the old;
    both stay, and the FAILED line names each path."""
    root = _root(tmp_path, {"keep": True}, name=FAULT_ROOT)
    settings = root / "settings.json"
    proc = _install(
        tmp_path,
        "-SettingsPath",
        str(settings),
        cwd=tmp_path,
        extra_env=_fault(tmp_path, "move-fails-target-gone", root),
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert not settings.exists()
    (tmp,) = [p for p in root.iterdir() if p.name.endswith(".tmp")]
    (bak,) = [p for p in root.iterdir() if ".bak-usage-" in p.name]
    assert "statusLine" in json.loads(tmp.read_text(encoding="utf-8"))
    assert json.loads(bak.read_text(encoding="utf-8")) == {"keep": True}
    flat = " ".join(proc.stdout.split())
    assert "settings.json is MISSING" in flat, proc.stdout
    assert str(tmp) in flat and str(bak) in flat, proc.stdout


def test_a_failed_move_on_a_root_with_no_settings_keeps_the_new_content(tmp_path: Path) -> None:
    """With no settings.json before the run there is no backup, so the complete temp file is the only
    copy of the new content; it stays, and the FAILED line names it."""
    root = _root(tmp_path, name=FAULT_ROOT)
    settings = root / "settings.json"
    proc = _install(
        tmp_path,
        "-SettingsPath",
        str(settings),
        cwd=tmp_path,
        extra_env=_fault(tmp_path, "move-fails", root),
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert not settings.exists()
    (tmp,) = [p for p in root.iterdir() if p.name.endswith(".tmp")]
    assert "statusLine" in json.loads(tmp.read_text(encoding="utf-8"))
    flat = " ".join(proc.stdout.split())
    assert "settings.json was not created" in flat and str(tmp) in flat, proc.stdout


def test_a_security_copy_that_fails_falls_back_to_the_in_place_write(tmp_path: Path) -> None:
    """A move would install the temp file's wider, inherited ACL, so a file whose own security cannot
    be copied is written in place, as before the swap existed: same file, new content, no temp file."""
    root = _root(tmp_path, {"keep": True}, name=FAULT_ROOT)
    settings = root / "settings.json"
    before = os.stat(settings).st_ino
    proc = _install(
        tmp_path,
        "-SettingsPath",
        str(settings),
        cwd=tmp_path,
        extra_env=_fault(tmp_path, "security-copy-fails", root),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert os.stat(settings).st_ino == before
    doc = json.loads(settings.read_text(encoding="utf-8"))
    assert doc["keep"] is True and "statusLine" in doc
    assert not [p.name for p in root.iterdir() if p.name.endswith(".tmp")]


@pytest.mark.parametrize(
    ("case", "root_name", "temp"),
    [
        # TMP and TEMP unset: GetTempPath falls back to USERPROFILE, the directory real roots live in.
        ("no explicit TEMP", FAULT_ROOT, None),
        # A real-root-shaped directory never carries the seam's leaf prefix.
        ("a .claude* root", ".claude-account-9", "tmp"),
        # The directory variable is required, not inferred.
        ("no fault directory", FAULT_ROOT, "tmp"),
        # TEMP set, but the root is not inside it.
        ("root outside TEMP", FAULT_ROOT, "other"),
        # The settings file is below the fault directory, not directly in it.
        ("nested settings", FAULT_ROOT, "tmp"),
    ],
)
def test_the_swap_fault_seam_never_fires_outside_its_fence(
    tmp_path: Path, case: str, root_name: str, temp: str | None
) -> None:
    """THE NEGATIVE CONTROLS FOR THE SEAM. Each case breaks one condition of the fence, so the real
    swap runs and a leaked value cannot leave a real root without its settings.json."""
    home = tmp_path / "profile"
    home.mkdir()
    root = home / root_name
    root.mkdir()
    where = root / "sub" if case == "nested settings" else root
    where.mkdir(exist_ok=True)
    settings = where / "settings.json"
    settings.write_text(json.dumps({"keep": True}), encoding="utf-8")
    env = {"MEFOR_TEST_STATUSLINE_SWAP_FAULT": "move-fails-target-gone", "USERPROFILE": str(home)}
    if case != "no fault directory":
        env["MEFOR_TEST_STATUSLINE_SWAP_FAULT_DIR"] = str(root)
    drop: tuple[str, ...] = ()
    if temp is None:
        drop = ("TEMP", "TMP")
    else:
        t = home if temp == "tmp" else tmp_path / "other"
        t.mkdir(exist_ok=True)
        env["TEMP"] = env["TMP"] = str(t)
    cmd = ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(INSTALL)]
    cmd += ["-HomeDir", str(_home(tmp_path)), "-CollectorPath", str(COLLECT)]
    cmd += ["-SettingsPath", str(settings)]
    full = _env(env)
    for k in drop:
        full.pop(k, None)
    proc = run_single(
        cmd, capture_output=True, text=True, timeout=TIMEOUT, check=False, env=full, cwd=tmp_path
    )
    assert proc.returncode == 0, (case, proc.stdout + proc.stderr)
    doc = json.loads(settings.read_text(encoding="utf-8"))
    assert doc["keep"] is True and "statusLine" in doc


def test_the_swap_fault_seam_fires_inside_its_fence(tmp_path: Path) -> None:
    """THE POSITIVE CONTROL. The same setup and the same mode as the negative cases, with every
    condition met, does fault, so their passing is the fence working and not a seam that never fires."""
    home = tmp_path / "profile"
    home.mkdir()
    root = home / FAULT_ROOT
    root.mkdir()
    settings = root / "settings.json"
    settings.write_text(json.dumps({"keep": True}), encoding="utf-8")
    proc = _install(
        tmp_path,
        "-SettingsPath",
        str(settings),
        cwd=tmp_path,
        extra_env={**_fault(home, "move-fails-target-gone", root), "USERPROFILE": str(home)},
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert not settings.exists()


# --- #7577: -HomeDir is read only where it is used ---------------------------------------------------


@pytest.mark.parametrize("how", ["USERPROFILE", "-HomeDir"])
@pytest.mark.parametrize("target", ["-SettingsPath", "-ConfigDir", "pin"])
def test_a_target_that_needs_no_home_dir_installs_with_one_on_a_gone_drive(
    tmp_path: Path, how: str, target: str
) -> None:
    """At least a -SettingsPath, a -ConfigDir and a CLAUDE_CONFIG_DIR-pinned install never read
    -HomeDir, so a home directory on a drive that is not there (USERPROFILE is the default) must not
    refuse them, as origin/main did not. -AllRoots does read it, and fails there on origin/main too."""
    gone = f"{_free_drive()}:\\Users\\nobody"
    root = _root(tmp_path, {"keep": True})
    settings = root / "settings.json"
    cmd = ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(INSTALL), "-CollectorPath"]
    cmd += [str(COLLECT)]
    env: dict[str, str] = {"USERPROFILE": gone}
    if target in ("-SettingsPath", "-ConfigDir"):
        cmd += [target, str(settings if target == "-SettingsPath" else root)]
    else:
        env["CLAUDE_CONFIG_DIR"] = str(root)
    if how == "-HomeDir":
        cmd += ["-HomeDir", gone]
        del env["USERPROFILE"]
    proc = _spawn(cmd, tmp_path, env)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    doc = json.loads(settings.read_text(encoding="utf-8"))
    assert doc["keep"] is True and "statusLine" in doc


@pytest.mark.parametrize("existing", [True, False])
def test_a_move_refused_past_its_retries_falls_back_to_the_in_place_write(
    tmp_path: Path, existing: bool
) -> None:
    """A reader that opens settings.json without delete sharing refuses the rename but never blocked
    the old in-place write, so after the retries the install still lands, written in place, with a
    warning, on a root that had a settings.json and on one that had none."""
    root = _root(tmp_path, {"keep": True} if existing else None, name=FAULT_ROOT)
    settings = root / "settings.json"
    before = os.stat(settings).st_ino if existing else None
    proc = _install(
        tmp_path,
        "-SettingsPath",
        str(settings),
        cwd=tmp_path,
        extra_env=_fault(tmp_path, "move-refused", root),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "written in place" in proc.stdout + proc.stderr
    if before is not None:
        assert os.stat(settings).st_ino == before
    doc = json.loads(settings.read_text(encoding="utf-8"))
    assert "statusLine" in doc and doc.get("keep", existing) is existing
    assert not [p.name for p in root.iterdir() if p.name.endswith(".tmp")]


@pytest.mark.parametrize("how", ["inherited preference", "-WarningAction Stop"])
def test_an_in_place_write_under_warning_stop_still_reports_wrote(tmp_path: Path, how: str) -> None:
    """Under -WarningAction Stop or an inherited $WarningPreference of Stop, the in-place fallback's
    warning threw after the write had landed, so a landed write reported FAILED and exited 1."""
    root = _root(tmp_path, {"keep": True}, name=FAULT_ROOT)
    settings = root / "settings.json"
    call = f"& {_q(INSTALL)} -HomeDir {_q(_home(tmp_path))} -CollectorPath {_q(COLLECT)}"
    call += f" -SettingsPath {_q(settings)}"
    if how == "-WarningAction Stop":
        call += " -WarningAction Stop"
    else:
        call = "$WarningPreference = 'Stop'; " + call
    proc = _spawn(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", f"{call}; exit $LASTEXITCODE"],
        tmp_path,
        _fault(tmp_path, "move-refused", root),
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    assert "FAILED" not in out and "WROTE" in out, out
    assert "written in place" in out, out
    doc = json.loads(settings.read_text(encoding="utf-8"))
    assert doc["keep"] is True and "statusLine" in doc


def test_a_write_denied_settings_file_is_not_replaced(tmp_path: Path) -> None:
    """A rename needs only delete access through the directory, so it could replace a settings.json
    that a Deny-Write ACE protects, which the in-place write could not. The write probe sends such a
    file to the in-place write, which fails as before and leaves it as it was."""
    root = _root(tmp_path, {"keep": True})
    settings = root / "settings.json"
    deny = (
        f"$p = {_q(settings)}; $a = Get-Acl -LiteralPath $p; "
        "$me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name; "
        "$a.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($me, 'WriteData', 'Deny')); "
        "Set-Acl -LiteralPath $p -AclObject $a; (Get-Item -LiteralPath $p).Attributes = 'Normal'"
    )
    undo = (
        f"$p = {_q(settings)}; $a = Get-Acl -LiteralPath $p; "
        "$me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name; "
        "[void]$a.RemoveAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($me, 'WriteData', 'Deny')); "
        "Set-Acl -LiteralPath $p -AclObject $a"
    )
    pw = ["pwsh", "-NoProfile", "-NonInteractive", "-Command"]
    assert _spawn([*pw, deny], tmp_path).returncode == 0
    try:
        proc = _install(tmp_path, "-SettingsPath", str(settings), cwd=tmp_path)
        assert proc.returncode == 1, proc.stdout + proc.stderr
        assert "was written in place" not in proc.stdout + proc.stderr
        assert json.loads(settings.read_text(encoding="utf-8")) == {"keep": True}
    finally:
        _spawn([*pw, undo], tmp_path)


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
    and default attributes. The old file's are copied onto the temp file before the move, so the new
    settings.json keeps them, as the in-place write did."""
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
    ino = os.stat(settings).st_ino
    proc = _install(tmp_path, "-SettingsPath", str(settings), cwd=tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    # A new file, so this is the move path keeping them and not the in-place fallback.
    assert os.stat(settings).st_ino != ino
    assert _spawn([*pw, probe], tmp_path).stdout.strip() == before
