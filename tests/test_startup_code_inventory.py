# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The start-up code inventory and the launch reading (vault BACKLOG #2701).

``messagefoundry/startupcode.py`` lists the ``.pth`` import lines and the ``sitecustomize`` /
``usercustomize`` modules that run when the interpreter starts, decides which are expected, and
reads whether the engine's own account can write the directories they come from. ``serve`` and
``supervise`` refuse on an unexpected one under ``[security].enforcement = enforce``.

Every arm has a control that shows it can fail: a file that is listed beside one that is not, a
recorded file beside the same file edited, a refused start beside the same start with nothing
planted. The launch reading is taken off real child interpreters, with and without the options.
"""

from __future__ import annotations

import argparse
import ctypes
import importlib
import json
import locale
import os
import shutil
import site as site_module
import subprocess
import sys
import venv
import warnings
from pathlib import Path

import pytest

from messagefoundry import startupcode
from messagefoundry.startupcode import (
    ISOLATED_LAUNCH_OPTIONS,
    InterpreterLaunch,
    StartupCodeItem,
    StartupPosture,
    read_startup_posture,
    startup_loosenings,
    startup_refusal,
)
from tests.test_isolated_launch import _decoy, _needs_install, _run
from tests.test_startup_attestation import _record_hash

_HARDENED = InterpreterLaunch(
    isolated=True, safe_path=True, ignore_environment=True, no_user_site=True
)
_PLAIN = InterpreterLaunch(
    isolated=False, safe_path=False, ignore_environment=False, no_user_site=False
)


def _names(posture: StartupPosture) -> list[str]:
    return [name for name, _ in startup_loosenings(posture)]


def _install_dist(site: Path, name: str, files: list[Path]) -> None:
    """A minimal installed distribution in ``site`` whose RECORD lists ``files``, which exist
    already. (``_build_wheel_install`` in the attestation tests writes its own files.)"""
    info = site / f"{name}-1.0.dist-info"
    info.mkdir()
    (info / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: {name}\nVersion: 1.0\n", encoding="utf-8"
    )
    rows = [
        f"{path.relative_to(site).as_posix()},{_record_hash(data)},{len(data)}"
        for path in files
        for data in [path.read_bytes()]
    ] + [f"{info.name}/RECORD,,"]
    (info / "RECORD").write_text("\n".join(rows) + "\n", encoding="utf-8")
    # The metadata reader caches a directory listing against the directory's modification time,
    # and two writes inside one clock tick leave that time unchanged.
    importlib.invalidate_caches()


@pytest.fixture
def site_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A site directory of our own, standing in for the interpreter's, and nothing else."""
    site = tmp_path / "site-packages"
    site.mkdir()
    monkeypatch.setattr(startupcode, "_site_dirs", lambda: [site])
    # The import path is searched for customize modules; keep it to the stand-in directory, and
    # keep this run's own PYTHONPATH and user-site setting out of the reading.
    monkeypatch.setattr(sys, "path", [str(site)])
    monkeypatch.delenv("PYTHONPATH", raising=False)
    monkeypatch.setattr(site_module, "ENABLE_USER_SITE", False)
    return site


def _customize(site: Path) -> list[StartupCodeItem]:
    """The customize modules found on the search path as it stands now."""
    return startupcode._customize_items([site], startupcode._search_path())


def _pth_verdicts(site: Path) -> dict[str, str]:
    return {Path(i.path).name: i.verdict for i in startupcode._pth_items(site)}


# --- the .pth arm ---------------------------------------------------------------------------------


def test_a_pth_file_is_start_up_code_only_when_a_line_begins_with_import(site_dir: Path) -> None:
    (site_dir / "paths-only.pth").write_text("some/dir\n# import os\n  import os\n", "utf-8")
    (site_dir / "runs-code.pth").write_text("some/dir\nimport os\n", "utf-8")
    (site_dir / "tab.pth").write_text("import\tos\n", "utf-8")
    # CONTROL: the two files that execute are listed, so an empty listing is not a blind reader.
    assert _pth_verdicts(site_dir) == {"runs-code.pth": "unrecorded", "tab.pth": "unrecorded"}


def test_a_hidden_pth_file_is_skipped_as_site_skips_it(site_dir: Path) -> None:
    (site_dir / ".hidden.pth").write_text("import os\n", "utf-8")
    (site_dir / "shown.pth").write_text("import os\n", "utf-8")
    assert list(_pth_verdicts(site_dir)) == ["shown.pth"]


def test_a_pth_file_a_package_records_is_expected_and_an_edited_one_is_not(site_dir: Path) -> None:
    pth = site_dir / "vendor-hook.pth"
    pth.write_text("import os\n", "utf-8")
    planted = site_dir / "planted.pth"
    planted.write_text("import os\n", "utf-8")
    _install_dist(site_dir, "vendor", [pth])
    items = {Path(i.path).name: i for i in startupcode._pth_items(site_dir)}
    assert items["vendor-hook.pth"].verdict == "recorded"
    assert items["vendor-hook.pth"].owner == "vendor"
    assert items["vendor-hook.pth"].expected
    # CONTROL: the file beside it, which nothing records.
    assert items["planted.pth"].verdict == "unrecorded" and not items["planted.pth"].expected
    # The same recorded file, edited after the install.
    pth.write_text("import os; import sys\n", "utf-8")
    edited = {Path(i.path).name: i for i in startupcode._pth_items(site_dir)}["vendor-hook.pth"]
    assert (edited.verdict, edited.owner, edited.expected) == ("modified", "vendor", False)


def test_the_packaging_tool_file_is_expected_only_with_its_own_content(
    site_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(startupcode, "_made_by_a_packaging_tool", lambda: True)
    pth = site_dir / "_virtualenv.pth"
    pth.write_text("import _virtualenv\n", "utf-8")
    assert _pth_verdicts(site_dir) == {"_virtualenv.pth": "packaging_tool"}
    # CONTROL: the same name with one more statement is not the tool's file.
    pth.write_text("import _virtualenv\nimport os\n", "utf-8")
    assert _pth_verdicts(site_dir) == {"_virtualenv.pth": "unrecorded"}


def test_the_packaging_tool_file_is_expected_only_where_that_tool_made_the_environment(
    tmp_path: Path, site_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``python -m venv`` writes no ``_virtualenv.pth``. One found in such an environment came from
    somewhere else, and its name does not make it expected."""
    (site_dir / "_virtualenv.pth").write_text("import _virtualenv\n", "utf-8")
    monkeypatch.setattr(sys, "prefix", str(tmp_path))
    cfg = tmp_path / "pyvenv.cfg"
    cfg.write_text("home = /usr/bin\nversion = 3.14.0\n", "utf-8")
    assert _pth_verdicts(site_dir) == {"_virtualenv.pth": "unrecorded"}
    for key in ("virtualenv = 20.31.2", "uv = 0.8.0"):
        cfg.write_text(f"home = /usr/bin\n{key}\n", "utf-8")
        assert _pth_verdicts(site_dir) == {"_virtualenv.pth": "packaging_tool"}, key
    # No pyvenv.cfg at all, as in an interpreter that is not a virtual environment.
    cfg.unlink()
    assert _pth_verdicts(site_dir) == {"_virtualenv.pth": "unrecorded"}


def test_a_pth_file_is_split_into_lines_the_way_site_splits_it(
    site_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``site`` reads a ``.pth`` as UTF-8 and falls back to the locale's encoding. Byte 0x85 is not
    UTF-8; in Latin-1 it is a line break. So ``site`` runs the import after it, and a reader that
    decoded the file another way would see one line that is not an import."""
    monkeypatch.setattr(locale, "getencoding", lambda: "latin-1")
    (site_dir / "split.pth").write_bytes(b"some/dir\x85import os\n")
    assert startupcode._executable_lines(site_dir / "split.pth") == ["import os"]
    # CONTROL: the same bytes without the break are one directory line.
    (site_dir / "one.pth").write_bytes(b"some/dir import os\n")
    assert startupcode._executable_lines(site_dir / "one.pth") == []
    # A file neither encoding can read was not read, and is listed for its RECORD row to judge.
    monkeypatch.setattr(locale, "getencoding", lambda: "ascii")
    assert startupcode._executable_lines(site_dir / "split.pth") is None
    assert "split.pth" in _pth_verdicts(site_dir)


def test_the_engines_own_editable_pth_never_counts(site_dir: Path) -> None:
    """An editable install of the engine writes a .pth into site-packages. In the shapes measured
    here it holds a directory and no import line, so it is not start-up code at all; where a build
    backend writes an import line instead, its RECORD lists the file. Either way a development
    start does not refuse."""
    (site_dir / "_editable_impl_messagefoundry.pth").write_text(r"C:\repo" + "\n", "utf-8")
    finder = site_dir / "__editable__.messagefoundry-0.0.pth"
    finder.write_text("import __editable___messagefoundry_finder; x.install()\n", "utf-8")
    _install_dist(site_dir, "messagefoundry", [finder])
    assert _pth_verdicts(site_dir) == {"__editable__.messagefoundry-0.0.pth": "recorded"}


# --- the customize-module arm ---------------------------------------------------------------------


def test_a_sitecustomize_on_the_import_path_is_found_and_not_run(
    tmp_path: Path, site_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    elsewhere = tmp_path / "on-pythonpath"
    elsewhere.mkdir()
    ran = tmp_path / "it-ran"
    (elsewhere / "sitecustomize.py").write_text(
        f"open({str(ran)!r}, 'w').close()\n", encoding="utf-8"
    )
    monkeypatch.setattr(sys, "path", [str(site_dir), str(elsewhere)])
    items = _customize(site_dir)
    assert [(i.kind, Path(i.path).parent.name, i.verdict) for i in items] == [
        ("sitecustomize", "on-pythonpath", "unrecorded")
    ]
    assert not ran.exists(), "the inventory imported the module it was listing"


def test_every_entry_is_searched_not_only_the_first_that_answers(
    tmp_path: Path, site_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first, second = tmp_path / "first", tmp_path / "second"
    for directory in (first, second):
        directory.mkdir()
        (directory / "sitecustomize.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr(sys, "path", [str(first), str(second)])
    found = [Path(i.path).parent.name for i in _customize(site_dir)]
    assert found == ["first", "second"]


def test_usercustomize_counts_only_where_the_user_site_is_on(
    site_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``site`` imports ``usercustomize`` only when the user site is enabled. It is off under
    ``-I`` and in a virtual environment, and a file that cannot run there must not refuse a
    start."""
    (site_dir / "usercustomize.py").write_text("x = 1\n", encoding="utf-8")
    assert _customize(site_dir) == []
    # CONTROL: with the user site on, the same file is listed.
    monkeypatch.setattr(site_module, "ENABLE_USER_SITE", True)
    assert [i.kind for i in _customize(site_dir)] == ["usercustomize"]


def test_the_path_the_children_inherit_is_searched_too(
    tmp_path: Path, site_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An isolated engine does not have PYTHONPATH on its own import path. Its Python children are
    handed the absolute entries and are not isolated, so a module there runs in them."""
    inherited = tmp_path / "inherited"
    inherited.mkdir()
    (inherited / "sitecustomize.py").write_text("x = 1\n", encoding="utf-8")
    assert _customize(site_dir) == []  # CONTROL: not on sys.path
    monkeypatch.setenv("PYTHONPATH", os.pathsep.join(["relative/entry", str(inherited)]))
    found = [Path(i.path).parent.name for i in _customize(site_dir)]
    assert found == ["inherited"]
    # The directory joins the ones checked for write access.
    assert str(inherited) in read_startup_posture().startup_dirs


def test_a_namespace_package_named_sitecustomize_runs_nothing_and_is_not_listed(
    tmp_path: Path, site_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "ns" / "sitecustomize").mkdir(parents=True)
    (tmp_path / "pkg" / "sitecustomize").mkdir(parents=True)
    (tmp_path / "pkg" / "sitecustomize" / "__init__.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr(sys, "path", [str(tmp_path / "ns"), str(tmp_path / "pkg")])
    found = [Path(i.path).parent.parent.name for i in _customize(site_dir)]
    # CONTROL: the package with an __init__ IS listed.
    assert found == ["pkg"]


def test_a_sitecustomize_in_the_interpreters_own_library_is_expected(
    tmp_path: Path, site_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stdlib = tmp_path / "stdlib"
    stdlib.mkdir()
    (stdlib / "sitecustomize.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr(sys, "path", [str(stdlib)])
    monkeypatch.setattr(
        startupcode, "_interpreter_dirs", lambda: frozenset({startupcode._norm(str(stdlib))})
    )
    assert [i.verdict for i in _customize(site_dir)] == ["interpreter"]
    # CONTROL: the same file where the interpreter's library is not.
    monkeypatch.setattr(startupcode, "_interpreter_dirs", lambda: frozenset())
    assert [i.verdict for i in _customize(site_dir)] == ["unrecorded"]


def test_a_sitecustomize_a_package_records_is_expected(site_dir: Path) -> None:
    module = site_dir / "sitecustomize.py"
    module.write_text("x = 1\n", encoding="utf-8")
    assert [i.verdict for i in _customize(site_dir)] == ["unrecorded"]
    _install_dist(site_dir, "hooks", [module])
    items = _customize(site_dir)
    assert [(i.verdict, i.owner) for i in items] == [("recorded", "hooks")]


def test_a_sitecustomize_a_package_ships_in_a_directory_of_its_own_is_expected(
    site_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Some packages ship the module in a sub-directory and put that directory on the import
    path. The file's RECORD row is in the site directory above it, not in the entry it was found
    on."""
    bootstrap = site_dir / "agent" / "bootstrap"
    bootstrap.mkdir(parents=True)
    module = bootstrap / "sitecustomize.py"
    module.write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr(sys, "path", [str(site_dir), str(bootstrap)])
    # CONTROL: nothing records it yet.
    assert [i.verdict for i in _customize(site_dir)] == ["unrecorded"]
    _install_dist(site_dir, "agent", [module])
    items = _customize(site_dir)
    assert [(i.verdict, i.owner) for i in items] == [("recorded", "agent")]


def test_the_interpreters_own_directories_are_the_base_interpreters(tmp_path: Path) -> None:
    """In a virtual environment the plain ``platstdlib`` path is the environment's own library
    folder. A module planted there must not read as the interpreter's, so the directories are
    asked for with the base prefixes. Read off a real virtual environment, made here, so the
    answer does not depend on how this test run was started."""
    environment = tmp_path / "venv"
    venv.EnvBuilder(with_pip=False).create(environment)
    scripts = environment / ("Scripts" if sys.platform == "win32" else "bin")
    probe = (
        "import json, sys, sysconfig; from messagefoundry import startupcode; "
        "print(json.dumps({'dirs': sorted(startupcode._interpreter_dirs()), "
        "'plain': startupcode._norm(sysconfig.get_path('platstdlib')), "
        "'prefix': startupcode._norm(sys.prefix)}))"
    )
    engine_root = str(Path(startupcode.__file__).resolve().parents[1])
    proc = subprocess.run(
        [str(scripts / "python"), "-c", probe],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": engine_root},
        timeout=50,
    )
    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout)
    assert report["dirs"], "CONTROL FAILED: no standard library directory was found"
    # CONTROL: the plain answer IS inside the environment, so the hazard is real here.
    assert Path(report["plain"]).is_relative_to(report["prefix"])
    inside = [d for d in report["dirs"] if Path(d).is_relative_to(report["prefix"])]
    assert not inside, f"the environment's own directory reads as the interpreter's: {inside}"


# --- the writable-directory arm -------------------------------------------------------------------


def test_a_directory_this_process_can_write_reads_as_writable(tmp_path: Path) -> None:
    assert startupcode._can_add_files(tmp_path) is True


def _plain_attempts(directory: Path) -> dict[str, bool]:
    """Whether a new file, and a new folder, can really be made in ``directory`` right now. Real
    attempts, undone at once: they are what the check is compared against.

    Only the file create is free of privilege. On Windows a folder create asks for backup
    semantics by itself, so a token with the restore privilege switched on makes one anywhere."""
    made = {"a file": False, "a folder": False}
    target = directory / f"attempt-{os.getpid()}.tmp"
    try:
        with open(target, "xb"):  # exclusive: an existing file must not pass as a new one
            made["a file"] = True
        target.unlink()
    except OSError:
        pass
    folder = directory / f"attempt-{os.getpid()}"
    try:
        folder.mkdir()
        made["a folder"] = True
        folder.rmdir()
    except OSError:
        pass
    return made


def _backup_intent_attempt(directory: Path) -> bool:
    """Whether a file can be created in ``directory`` when the create asks for backup semantics,
    which is how the check itself has to open a directory. Windows grants such a create to a
    token that holds the restore privilege switched on, whatever the directory's permissions say.
    The file is deleted when its handle closes."""
    if sys.platform != "win32":  # also what narrows the ctypes names below for mypy
        raise RuntimeError("backup semantics are a Windows notion")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    kernel32.CreateFileW.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    generic_write_and_delete = 0x40000000 | 0x00010000
    create_new = 1
    backup_semantics_delete_on_close = 0x02000000 | 0x04000000
    handle = kernel32.CreateFileW(
        str(directory / f"backup-intent-{os.getpid()}.tmp"),
        generic_write_and_delete,
        0,
        None,
        create_new,
        backup_semantics_delete_on_close,
        None,
    )
    if handle is None or handle == ctypes.c_void_p(-1).value:
        return False
    kernel32.CloseHandle(handle)
    return True


class _LUID(ctypes.Structure):
    _fields_ = [("LowPart", ctypes.c_uint32), ("HighPart", ctypes.c_int32)]


class _PRIVILEGE_SET_ONE(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", ctypes.c_uint32),
        ("Control", ctypes.c_uint32),
        ("Luid", _LUID),
        ("Attributes", ctypes.c_uint32),
    ]


def _privilege_switched_on(name: str) -> bool | None:
    """Whether this process's token holds privilege ``name`` switched on. None when that could not
    be read. Only ever used to say WHY a create worked; no assertion rests on it but its own."""
    if sys.platform != "win32":  # also what narrows the ctypes names below for mypy
        raise RuntimeError("a token privilege is a Windows notion")
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    advapi32.OpenProcessToken.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.LookupPrivilegeValueW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.POINTER(_LUID),
    ]
    advapi32.PrivilegeCheck.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(_PRIVILEGE_SET_ONE),
        ctypes.POINTER(ctypes.c_int32),
    ]
    token_query = 0x0008
    token = ctypes.c_void_p()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), token_query, ctypes.byref(token)
    ):
        return None
    try:
        wanted = _PRIVILEGE_SET_ONE(PrivilegeCount=1, Control=1)  # 1: all of them are necessary
        if not advapi32.LookupPrivilegeValueW(None, name, ctypes.byref(wanted.Luid)):
            return None
        held = ctypes.c_int32(0)
        if not advapi32.PrivilegeCheck(token, ctypes.byref(wanted), ctypes.byref(held)):
            return None
        return bool(held.value)
    finally:
        kernel32.CloseHandle(token)


_windows_only = pytest.mark.skipif(sys.platform != "win32", reason="Windows tokens and DACLs")


@_windows_only
def test_the_privilege_reader_tells_a_privilege_that_is_on_from_one_that_is_not() -> None:
    """The reader only feeds a warning, so its own control is here. Every token has the
    change-notify privilege switched on. No test process is expected to hold the one that creates
    tokens, and a name Windows does not know is unreadable, not off."""
    assert _privilege_switched_on("SeChangeNotifyPrivilege") is True
    assert _privilege_switched_on("SeCreateTokenPrivilege") is False
    assert _privilege_switched_on("SeNoSuchPrivilege") is None


@_windows_only
def test_the_windows_write_check_agrees_with_a_real_attempt_behind_a_deny_entry(
    tmp_path: Path,
) -> None:
    """The check opens the directory and lets Windows judge, so it is compared with real creates
    and never with what an access list was expected to do.

    THAT DIFFERENCE IS WHY THIS TEST CHANGED. It used to assert that a deny entry makes the check
    answer no. On a hosted Windows runner the test process is an elevated administrator, and the
    check answered yes on both Server legs. So the last arm now makes the attempts itself and
    holds the check to their result, whichever it is. Where a create worked it warns with which
    ones, and with whether the restore privilege is switched on. That privilege is the likely way
    through a deny entry: Windows honours it on a create that asks for backup semantics. The
    reading is the hosted leg's to give. This machine's unelevated shell cannot give it.

    On a host whose process holds that privilege this test can only catch a check that says no
    too often. The arms where the answer must be no, whoever runs the suite, are in the next
    test, which asks under tokens with their privileges removed."""
    if shutil.which("icacls") is None:
        pytest.skip("SKIP (nothing run): icacls not on PATH")
    locked = tmp_path / "locked"
    locked.mkdir()

    def deny(rights: str) -> None:
        subprocess.run(["icacls", str(locked), "/remove:d", "*S-1-1-0"], capture_output=True)
        subprocess.run(
            ["icacls", str(locked), "/deny", f"*S-1-1-0:({rights})"],
            check=True,
            capture_output=True,
        )

    # CONTROL: writable before any entry, by the check and by each kind of real attempt.
    assert startupcode._can_add_files(locked) is True
    assert _plain_attempts(locked) == {"a file": True, "a folder": True}
    assert _backup_intent_attempt(locked) is True
    try:
        # A customize module may be a package, so the right to add a folder counts as well.
        deny("WD")
        assert _plain_attempts(locked)["a folder"], (
            "CONTROL FAILED: the folder right was denied too"
        )
        assert startupcode._can_add_files(locked) is True
        deny("WD,AD")
        attempts = {
            **_plain_attempts(locked),
            "a file, asking for backup semantics": _backup_intent_attempt(locked),
        }
        worked = sorted(what for what, made in attempts.items() if made)
        assert startupcode._can_add_files(locked) is bool(worked), attempts
        if worked:
            warnings.warn(
                "behind an entry that denies Everyone the rights to add a file and a folder, "
                f"this process still created: {', '.join(worked)}. SeRestorePrivilege switched "
                f"on: {_privilege_switched_on('SeRestorePrivilege')}. The write check answered "
                "yes, which is the true answer for this token.",
                stacklevel=1,
            )
    finally:
        subprocess.run(["icacls", str(locked), "/remove:d", "*S-1-1-0"], capture_output=True)


#: Run under another token by the next test. For each directory it reports what the write check
#: said, and whether a new file and a new folder could really be made. Anything that goes wrong is
#: written into the report, because the child has no console to say it on.
_WRITE_CHECK_CHILD = """\
import json
import os
import sys
import traceback
from pathlib import Path

engine_root, report, *directories = sys.argv[1:]
try:
    # The copy of the engine the parent test imported, whatever this interpreter has installed.
    sys.path.insert(0, engine_root)
    from messagefoundry import startupcode

    def made(directory, folder):
        target = os.path.join(directory, "attempt-%d" % os.getpid())
        try:
            if folder:
                os.mkdir(target)
                os.rmdir(target)
            else:
                os.close(os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY))
                os.remove(target)
        except OSError:
            return False
        return True

    payload = {
        "readings": {
            Path(d).name: [startupcode._can_add_files(Path(d)), made(d, False), made(d, True)]
            for d in directories
        }
    }
except BaseException:
    payload = {"error": traceback.format_exc()}
Path(report).write_text(json.dumps(payload), encoding="utf-8")
"""


@_windows_only
def test_the_windows_write_check_follows_the_token_that_asks(tmp_path: Path) -> None:
    """The check must answer for the token that asks, not for the account's permissions on paper.
    The installer gives the default service account a write-restricted token with a one-entry
    privilege list (``docs/SERVICE.md``, "Restrict the service token"), so that is one of the
    tokens asked here.

    Five directories, read under two stand-in tokens, and each reading is the check beside a real
    file create and a real folder create:

    * ``by-name`` grants this account by name. Both tokens may add to it.
    * ``by-group`` grants only Users and Authenticated Users. A token with its privileges removed
      may add to it. A write-restricted one may not: that is the restriction, and a check that
      read the access list alone would say yes.
    * ``not-granted`` gives this account read access only. Neither token may add to it.
    * ``deny-file`` denies Everyone the right to add a file and not the right to add a folder. A
      customize module may be a package, so the check must still say yes.
    * ``deny-both`` denies both rights. The check must say no.

    The stand-in tokens are copies of this process's own (``tests/_restricted_token.py``) with
    every privilege but one removed. So no elevation is needed, no privilege can answer for the
    access list, and the same arms run on a developer's machine and on an elevated hosted runner.
    These are the arms that can catch a check that says yes too often there."""
    # Imported here: these modules are test files too, and only this Windows-only test needs
    # them. The DACL builder also removes an explicit OWNER RIGHTS entry, which a hosted runner's
    # temp directory can carry and which would let a child write as the directory's owner.
    from tests._restricted_token import (
        DISABLE_MAX_PRIVILEGE,
        WRITE_RESTRICTED,
        spawn_restricted,
    )
    from tests.test_service_token_hardening import _probe, _stand_in_sids
    from tests.test_store_trio_acl import _build_dir_dacl, _icacls, _release
    from tests.test_store_trio_acl import _run as run_checked

    probe = _probe()
    me, restricting = _stand_in_sids(probe)
    script = tmp_path / "write_check_child.py"
    script.write_text(_WRITE_CHECK_CHILD, encoding="utf-8")
    engine_root = str(Path(startupcode.__file__).resolve().parents[1])
    names = ("by-name", "by-group", "not-granted", "deny-file", "deny-both")
    by_name, by_group, not_granted, deny_file, deny_both = (tmp_path / name for name in names)
    reports = tmp_path / "reports"
    directories = (by_name, by_group, not_granted, deny_file, deny_both)
    for directory in (*directories, reports):
        directory.mkdir()
    system, mine = "*S-1-5-18:(OI)(CI)F", f"*{me}:(OI)(CI)M"
    everyone = "*S-1-1-0"
    try:
        _build_dir_dacl(by_name, mine, system)
        _build_dir_dacl(by_group, *(f"*{sid}:(OI)(CI)M" for sid in probe.BROAD_GROUPS), system)
        _build_dir_dacl(not_granted, f"*{me}:(OI)(CI)RX", system)
        _build_dir_dacl(deny_file, mine, system)
        run_checked([_icacls(), str(deny_file), "/deny", f"{everyone}:(WD)"])
        _build_dir_dacl(deny_both, mine, system)
        run_checked([_icacls(), str(deny_both), "/deny", f"{everyone}:(WD,AD)"])
        _build_dir_dacl(reports, mine, system)

        def under(name: str, restricting_sids: list[str], flags: int) -> dict[str, list[bool]]:
            report = reports / f"{name}.json"
            argv = [sys.executable, "-B", str(script), engine_root, str(report)]
            child = spawn_restricted(
                [*argv, *map(str, directories)], restricting_sids=restricting_sids, flags=flags
            )
            # Well inside the per-test time limit, twice over, so a hung child is reported here.
            exit_code = child.wait(25)
            assert report.exists(), f"the {name} child wrote no report (exit code {exit_code})"
            payload = json.loads(report.read_text(encoding="utf-8"))
            assert "error" not in payload, f"the {name} child failed:\n{payload['error']}"
            readings: dict[str, list[bool]] = payload["readings"]
            return readings

        # The token the hardened service gets, and one that only has its privileges removed.
        hardened = under("hardened", restricting, WRITE_RESTRICTED | DISABLE_MAX_PRIVILEGE)
        stripped = under("stripped", [], DISABLE_MAX_PRIVILEGE)
        ordinary = {
            d.name: [startupcode._can_add_files(d), _plain_attempts(d)["a file"]]
            for d in (by_name, by_group)
        }
    finally:
        for directory in (deny_file, deny_both):
            subprocess.run([_icacls(), str(directory), "/remove:d", everyone], capture_output=True)
        for directory in (*directories, reports):
            _release(directory, me)

    # [the check, a new file was made, a new folder was made]
    yes, no, folder_only = [True, True, True], [False, False, False], [True, False, True]
    denied = {"not-granted": no, "deny-file": folder_only, "deny-both": no}
    assert hardened == {"by-name": yes, "by-group": no, **denied}, hardened
    assert stripped == {"by-name": yes, "by-group": yes, **denied}, stripped
    # In every reading the check said yes exactly when a real create worked.
    for reading in (*hardened.values(), *stripped.values()):
        assert reading[0] is (reading[1] or reading[2]), (hardened, stripped)
    # CONTROL: the same by-group directory is writable to this process, so the hardened token's
    # refusal there comes from the restriction and not from the directory.
    assert ordinary == {"by-name": [True, True], "by-group": [True, True]}, ordinary


@pytest.mark.skipif(sys.platform == "win32", reason="the POSIX arm of the check")
def test_the_posix_write_check_agrees_with_a_real_attempt(tmp_path: Path) -> None:
    """A read-only directory, with the check held to a real create and not to the mode bits: for
    an ordinary account both say no, and for root both say yes."""
    locked = tmp_path / "locked"
    locked.mkdir()
    assert startupcode._can_add_files(locked) is True  # CONTROL
    locked.chmod(0o555)
    try:
        really = _plain_attempts(locked)["a file"]
        assert startupcode._can_add_files(locked) is really
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            assert really is False, "CONTROL FAILED: a read-only directory took a new file"
    finally:
        locked.chmod(0o755)


def test_the_reading_checks_every_directory_start_up_code_is_read_from(
    tmp_path: Path, site_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A customize module is looked for on every import-path directory, so each of those is a
    place to plant one, not only the site directories. An entry that is not a directory is not."""
    on_path = tmp_path / "on-the-import-path"
    on_path.mkdir()
    archive = tmp_path / "bundle.zip"
    archive.write_bytes(b"")
    monkeypatch.setattr(sys, "path", [str(site_dir), str(on_path), str(archive), "missing-dir"])
    monkeypatch.setattr(startupcode, "_can_add_files", lambda d: d == on_path)
    reading = read_startup_posture()
    assert reading.startup_dirs == (str(site_dir), str(on_path))
    assert reading.writable_startup_dirs == (str(on_path),)


def test_the_reading_lists_the_writable_start_up_directories(
    site_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(startupcode, "_can_add_files", lambda d: True)
    assert read_startup_posture().writable_startup_dirs == (str(site_dir),)
    monkeypatch.setattr(startupcode, "_can_add_files", lambda d: False)
    assert read_startup_posture().writable_startup_dirs == ()
    monkeypatch.setattr(startupcode, "_can_add_files", lambda d: None)
    reading = read_startup_posture()
    assert reading.unchecked_startup_dirs == (str(site_dir),) and not reading.writable_startup_dirs


# --- what is refused and what is reported ---------------------------------------------------------

_PLANTED = StartupCodeItem("pth", "/site/planted.pth", "unrecorded")
_KNOWN = StartupCodeItem("pth", "/site/distutils-precedence.pth", "recorded", "setuptools")


def test_only_unexpected_start_up_code_refuses() -> None:
    assert startup_refusal(StartupPosture(launch=_HARDENED, items=(_KNOWN,))) is None
    refusal = startup_refusal(StartupPosture(launch=_HARDENED, items=(_KNOWN, _PLANTED)))
    assert refusal is not None and "/site/planted.pth (unrecorded)" in refusal
    assert "distutils-precedence" not in refusal
    # A plain launch with a writable site directory is reported, never refused: a developer's own
    # environment is both.
    developer = StartupPosture(launch=_PLAIN, writable_startup_dirs=("/venv",))
    assert startup_refusal(developer) is None
    assert _names(developer) == ["interpreter_not_isolated", "startup_directory_writable"]


def test_the_hardened_launch_reports_nothing() -> None:
    assert _names(StartupPosture(launch=_HARDENED, items=(_KNOWN,))) == []


@pytest.mark.parametrize(
    ("posture", "expected"),
    [
        (StartupPosture(launch=_PLAIN), ["interpreter_not_isolated"]),
        (StartupPosture(launch=_HARDENED, items=(_PLANTED,)), ["startup_code_unexpected"]),
        (
            StartupPosture(launch=_HARDENED, writable_startup_dirs=("/v",)),
            ["startup_directory_writable"],
        ),
        (
            StartupPosture(launch=_HARDENED, unchecked_startup_dirs=("/v",)),
            ["startup_directory_unchecked"],
        ),
        (
            StartupPosture(
                launch=InterpreterLaunch(
                    True,
                    True,
                    True,
                    True,
                    code_path_variables=("PYTHONPATH",),
                    reaching_children=("PYTHONPATH",),
                )
            ),
            ["python_variables_reach_children"],
        ),
        # A variable that is set and reaches no child, such as a PYTHONPATH with no absolute
        # entry, is not reported for the children.
        (
            StartupPosture(
                launch=InterpreterLaunch(
                    True, True, True, True, code_path_variables=("PYTHONPATH",)
                )
            ),
            [],
        ),
    ],
)
def test_each_deviation_has_its_own_name(posture: StartupPosture, expected: list[str]) -> None:
    assert _names(posture) == expected


def test_a_variable_the_engine_honours_is_named_in_the_not_isolated_entry() -> None:
    honoured = InterpreterLaunch(False, False, False, False, code_path_variables=("PYTHONPATH",))
    (risk,) = [r for n, r in startup_loosenings(StartupPosture(launch=honoured))]
    assert "PYTHONPATH is set in its environment now" in risk
    assert "It reads the PYTHON* environment variables" in risk
    # CONTROL: under -E the same variable is not honoured, and the entry does not claim it is.
    # The children still receive it, so that entry is there as well.
    ignored = InterpreterLaunch(
        False,
        False,
        True,
        False,
        code_path_variables=("PYTHONPATH",),
        reaching_children=("PYTHONPATH",),
    )
    entries = dict(startup_loosenings(StartupPosture(launch=ignored)))
    assert list(entries) == ["interpreter_not_isolated", "python_variables_reach_children"]
    assert "is set in its environment now" not in entries["interpreter_not_isolated"]
    assert "It reads the PYTHON*" not in entries["interpreter_not_isolated"]


def test_the_launch_reading_names_a_variable_only_when_it_holds_something(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A variable set to nothing changes nothing. And the child builders drop a ``PYTHONPATH``
    entry that is not absolute, so a variable holding only those reaches no child."""
    for name in startupcode._CODE_PATH_VARIABLES:
        monkeypatch.delenv(name, raising=False)

    def reading() -> tuple[tuple[str, ...], tuple[str, ...]]:
        launch = startupcode._interpreter_launch()
        return launch.code_path_variables, launch.reaching_children

    monkeypatch.setenv("PYTHONPATH", "")
    assert reading() == ((), ())
    monkeypatch.setenv("PYTHONPATH", "relative/entry")
    assert reading() == (("PYTHONPATH",), ())
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    assert reading() == (("PYTHONPATH",), ("PYTHONPATH",))
    monkeypatch.setenv("PYTHONHOME", str(tmp_path))
    assert reading()[1] == ("PYTHONHOME", "PYTHONPATH")


def test_an_import_path_entry_that_is_not_text_does_not_stop_the_reading(
    site_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The import system skips such an entry. The reading runs at every start, so it must too."""
    monkeypatch.setattr(sys, "path", [str(site_dir), os.fsencode(str(site_dir)), None])
    assert read_startup_posture().startup_dirs == (str(site_dir),)


def test_a_file_name_cannot_break_the_log_line() -> None:
    nasty = StartupCodeItem("pth", "/site/x\nFAKE ENTRY.pth", "unrecorded")
    refusal = startup_refusal(StartupPosture(launch=_HARDENED, items=(nasty,)))
    assert refusal is not None and "\n" not in refusal


def test_the_reported_variables_are_ones_the_children_inherit() -> None:
    """The children-entry says a Python child honours these. It does because the child builders
    pass each one by name; this ties the two lists."""
    from messagefoundry import childenv

    assert set(startupcode._CODE_PATH_VARIABLES) <= childenv._INTERPRETER_NAMES


# --- the launch, read off real interpreters -------------------------------------------------------

_CHILD_REPORT = """
import json
from messagefoundry.config.settings import (
    AlertsSettings, ApiSettings, AuthSettings, SecretRotationSettings, SecuritySettings,
    StoreSettings, security_loosenings,
)
from messagefoundry.remotedebug import install_remote_debug_guard, remote_debug_posture
from messagefoundry.startupcode import read_startup_posture
import sys
install_remote_debug_guard()
startup = read_startup_posture()
names = [name for name, _ in security_loosenings(
    SecuritySettings(), StoreSettings(), AuthSettings(), AlertsSettings(), SecretRotationSettings(),
    cleartext_hops=(), expiry_relaxed_hops=(), hostname_unchecked_hops=(), query_credential_hops=(),
    unverified_db_hops=(), attested_hops=(), revocation_attested_hops=(), api=ApiSettings(),
    store_privilege=None, audit_chain_unkeyed=None, remote_debug=remote_debug_posture(),
    startup=startup,
)]
print(json.dumps({"names": names, "isolated": startup.launch.isolated,
                  "safe_path": startup.launch.safe_path, "path": sys.path}))
"""


@_needs_install
def test_the_isolated_launch_drops_both_entries_and_a_plain_one_has_both(tmp_path: Path) -> None:
    """The shipped launches pass :data:`ISOLATED_LAUNCH_OPTIONS`. With them, neither
    ``interpreter_not_isolated`` nor ``remote_debug_enabled`` is in the registry's list. The decoy
    package is on PYTHONPATH and is the working directory, and an isolated child ignores both. The
    control is the same child without the options: the decoy wins there, before the report."""
    decoy = _decoy(tmp_path)
    hardened = _run(ISOLATED_LAUNCH_OPTIONS, "-c", _CHILD_REPORT, cwd=decoy, PYTHONPATH=str(decoy))
    assert hardened.returncode == 0, hardened.stderr
    report = json.loads(hardened.stdout)
    assert report["isolated"] is True and report["safe_path"] is True
    assert "interpreter_not_isolated" not in report["names"]
    assert "remote_debug_enabled" not in report["names"]
    assert not any("decoy" in str(p) for p in report["path"])
    plain = _run((), "-c", _CHILD_REPORT, cwd=decoy, PYTHONPATH=str(decoy))
    assert plain.returncode != 0 and "DECOY" in plain.stderr, (
        "CONTROL FAILED: the decoy on PYTHONPATH did not win in a plain child"
    )


@_needs_install
def test_a_plain_child_reports_both_entries(tmp_path: Path) -> None:
    """The other half of the control, without the decoy in the way: an interpreter started with
    no options names both."""
    plain = _run((), "-c", _CHILD_REPORT, cwd=tmp_path)
    assert plain.returncode == 0, plain.stderr
    names = json.loads(plain.stdout)["names"]
    assert "interpreter_not_isolated" in names and "remote_debug_enabled" in names


# --- serve refuses under enforce, and reports under warn ------------------------------------------

_SAMPLES_CONFIG = Path(__file__).resolve().parents[1] / "samples" / "config"


def _serve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, posture: StartupPosture, *, warn: bool
) -> int:
    from messagefoundry.__main__ import main

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", "x" * 44)
    if warn:
        monkeypatch.setenv("MEFOR_SECURITY_ENFORCEMENT", "warn")
    else:
        monkeypatch.delenv("MEFOR_SECURITY_ENFORCEMENT", raising=False)
    monkeypatch.setattr(startupcode, "startup_posture", lambda: posture)
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    return main(["serve", "--config", str(_SAMPLES_CONFIG), "--env", "dev"])


def test_serve_refuses_unexpected_start_up_code_under_enforce(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    planted = StartupPosture(launch=_HARDENED, items=(_PLANTED,))
    assert _serve(tmp_path, monkeypatch, planted, warn=False) == 2
    err = capsys.readouterr().err
    assert "refusing to start: start-up code the engine does not know" in err
    assert "/site/planted.pth (unrecorded)" in err
    # Before any side effect: nothing was minted or opened in the working directory.
    assert not any(tmp_path.iterdir()), sorted(p.name for p in tmp_path.iterdir())


def test_serve_does_not_refuse_known_start_up_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The control for the refusal above: the same start, with only expected start-up code. It
    may stop at some later gate; it must not stop at this one."""
    _serve(tmp_path, monkeypatch, StartupPosture(launch=_HARDENED, items=(_KNOWN,)), warn=False)
    assert "start-up code the engine does not know" not in capsys.readouterr().err


def test_serve_reports_unexpected_start_up_code_under_warn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    planted = StartupPosture(launch=_HARDENED, items=(_PLANTED,))
    _serve(tmp_path, monkeypatch, planted, warn=True)
    captured = capsys.readouterr()
    assert "refusing to start: start-up code" not in captured.err
    # serve installs its own stdout handler, so the loosening line is read from stdout.
    assert "startup_code_unexpected (start-up code the engine does not know" in captured.out


# --- supervise makes the same check before it starts an engine shard ------------------------------


def _supervise(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, posture: StartupPosture, *, warn: bool
) -> tuple[int, list[str]]:
    """``_supervise`` with the fleet stubbed out: its return code and the configs it would have
    spawned. No store key is set, so a run that gets past the start-up gate stops at the at-rest
    gate. Logging setup is stubbed, so the root handlers are not left bound to this test's
    capture buffer."""
    from messagefoundry import __main__ as cli

    spawned: list[str] = []

    async def fake_supervise(config: str, **kwargs: object) -> int:
        spawned.append(config)
        return 0

    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY", raising=False)
    if warn:
        monkeypatch.setenv("MEFOR_SECURITY_ENFORCEMENT", "warn")
    else:
        monkeypatch.delenv("MEFOR_SECURITY_ENFORCEMENT", raising=False)
    monkeypatch.setattr(startupcode, "startup_posture", lambda: posture)
    monkeypatch.setattr("messagefoundry.pipeline.supervisor.supervise", fake_supervise)
    monkeypatch.setattr(cli, "configure_logging", lambda *args, **kwargs: None)
    args = argparse.Namespace(
        config=str(_SAMPLES_CONFIG),
        db=str(tmp_path / "mefor.db"),
        base_port=8765,
        env="dev",
        service_config=None,
        project_root=str(tmp_path),
    )
    return cli._supervise(args), spawned


def test_supervise_refuses_unexpected_start_up_code_before_it_starts_an_engine_shard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    planted = StartupPosture(launch=_HARDENED, items=(_PLANTED,))
    rc, spawned = _supervise(tmp_path, monkeypatch, planted, warn=False)
    err = capsys.readouterr().err
    assert rc == 2 and not spawned
    assert "start-up code the engine does not know" in err
    assert "refusing to start the fleet" in err
    # This gate, and not the at-rest gate after it, is what stopped the start.
    assert "store key" not in err


def test_supervise_does_not_refuse_known_start_up_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The control: the same start with only expected start-up code gets past this gate, and
    stops at the next one."""
    known = StartupPosture(launch=_HARDENED, items=(_KNOWN,))
    rc, spawned = _supervise(tmp_path, monkeypatch, known, warn=False)
    err = capsys.readouterr().err
    assert "start-up code the engine does not know" not in err
    assert rc == 2 and "store key" in err and not spawned


def test_supervise_reports_unexpected_start_up_code_under_warn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    planted = StartupPosture(launch=_PLAIN, items=(_PLANTED,))
    with caplog.at_level("WARNING", logger="messagefoundry.__main__"):
        _supervise(tmp_path, monkeypatch, planted, warn=True)
    assert "start-up code the engine does not know" not in capsys.readouterr().err
    logged = [record.getMessage() for record in caplog.records]
    assert any(line.startswith("[security] startup_code_unexpected:") for line in logged), logged
    assert any(line.startswith("[security] interpreter_not_isolated:") for line in logged), logged
