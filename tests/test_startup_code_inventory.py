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

import base64
import hashlib
import importlib
import json
import os
import shutil
import subprocess
import sys
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

_HARDENED = InterpreterLaunch(
    isolated=True, safe_path=True, ignore_environment=True, no_user_site=True
)
_PLAIN = InterpreterLaunch(
    isolated=False, safe_path=False, ignore_environment=False, no_user_site=False
)


def _names(posture: StartupPosture) -> list[str]:
    return [name for name, _ in startup_loosenings(posture)]


def _record_row(path: Path, root: Path) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(path.read_bytes()).digest()).rstrip(b"=")
    return f"{path.relative_to(root).as_posix()},sha256={digest.decode()},{path.stat().st_size}"


def _install_dist(site: Path, name: str, files: list[Path]) -> None:
    """A minimal installed distribution in ``site`` whose RECORD lists ``files``."""
    info = site / f"{name}-1.0.dist-info"
    info.mkdir()
    (info / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: {name}\nVersion: 1.0\n", encoding="utf-8"
    )
    rows = [_record_row(path, site) for path in files] + [f"{info.name}/RECORD,,"]
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
    # The import path is searched for customize modules; keep it to the stand-in directory.
    monkeypatch.setattr(sys, "path", [str(site)])
    return site


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


def test_the_packaging_tool_file_is_expected_only_with_its_own_content(site_dir: Path) -> None:
    pth = site_dir / "_virtualenv.pth"
    pth.write_text("import _virtualenv\n", "utf-8")
    assert _pth_verdicts(site_dir) == {"_virtualenv.pth": "packaging_tool"}
    # CONTROL: the same name with one more statement is not the tool's file.
    pth.write_text("import _virtualenv\nimport os\n", "utf-8")
    assert _pth_verdicts(site_dir) == {"_virtualenv.pth": "unrecorded"}


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
    items = startupcode._customize_items([site_dir])
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
        (directory / "usercustomize.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr(sys, "path", [str(first), str(second)])
    found = [Path(i.path).parent.name for i in startupcode._customize_items([site_dir])]
    assert found == ["first", "second"]


def test_a_namespace_package_named_sitecustomize_runs_nothing_and_is_not_listed(
    tmp_path: Path, site_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "ns" / "sitecustomize").mkdir(parents=True)
    (tmp_path / "pkg" / "sitecustomize").mkdir(parents=True)
    (tmp_path / "pkg" / "sitecustomize" / "__init__.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr(sys, "path", [str(tmp_path / "ns"), str(tmp_path / "pkg")])
    found = [Path(i.path).parent.parent.name for i in startupcode._customize_items([site_dir])]
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
    assert [i.verdict for i in startupcode._customize_items([site_dir])] == ["interpreter"]
    # CONTROL: the same file where the interpreter's library is not.
    monkeypatch.setattr(startupcode, "_interpreter_dirs", lambda: frozenset())
    assert [i.verdict for i in startupcode._customize_items([site_dir])] == ["unrecorded"]


def test_a_sitecustomize_a_package_records_is_expected(site_dir: Path) -> None:
    module = site_dir / "sitecustomize.py"
    module.write_text("x = 1\n", encoding="utf-8")
    assert [i.verdict for i in startupcode._customize_items([site_dir])] == ["unrecorded"]
    _install_dist(site_dir, "hooks", [module])
    items = startupcode._customize_items([site_dir])
    assert [(i.verdict, i.owner) for i in items] == [("recorded", "hooks")]


# --- the writable-directory arm -------------------------------------------------------------------


def test_a_directory_this_process_can_write_reads_as_writable(tmp_path: Path) -> None:
    assert startupcode._can_add_files(tmp_path) is True


@pytest.mark.skipif(sys.platform != "win32", reason="the Windows arm of the check")
def test_a_directory_this_process_may_not_add_files_to_reads_as_not_writable(
    tmp_path: Path,
) -> None:
    """The Windows check asks the system's own access check, so the control is a real ACL: deny
    Everyone the right to add a file, then take the entry away again."""
    if shutil.which("icacls") is None:
        pytest.skip("SKIP (nothing run): icacls not on PATH")
    locked = tmp_path / "locked"
    locked.mkdir()
    assert startupcode._can_add_files(locked) is True  # CONTROL: writable before the entry
    subprocess.run(
        ["icacls", str(locked), "/deny", "*S-1-1-0:(WD)"], check=True, capture_output=True
    )
    try:
        assert startupcode._can_add_files(locked) is False
    finally:
        subprocess.run(["icacls", str(locked), "/remove:d", "*S-1-1-0"], capture_output=True)


@pytest.mark.skipif(sys.platform == "win32", reason="the POSIX arm of the check")
def test_a_read_only_directory_reads_as_not_writable(tmp_path: Path) -> None:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        pytest.skip("SKIP (nothing run): root may write a read-only directory")
    locked = tmp_path / "locked"
    locked.mkdir()
    assert startupcode._can_add_files(locked) is True  # CONTROL
    locked.chmod(0o555)
    try:
        assert startupcode._can_add_files(locked) is False
    finally:
        locked.chmod(0o755)


def test_the_reading_lists_the_writable_site_directories(
    site_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(startupcode, "_can_add_files", lambda d: True)
    assert read_startup_posture().writable_site_dirs == (str(site_dir),)
    monkeypatch.setattr(startupcode, "_can_add_files", lambda d: False)
    assert read_startup_posture().writable_site_dirs == ()
    monkeypatch.setattr(startupcode, "_can_add_files", lambda d: None)
    reading = read_startup_posture()
    assert reading.unchecked_site_dirs == (str(site_dir),) and not reading.writable_site_dirs


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
    developer = StartupPosture(launch=_PLAIN, writable_site_dirs=("/venv",))
    assert startup_refusal(developer) is None
    assert _names(developer) == ["interpreter_not_isolated", "site_packages_writable"]


def test_the_hardened_launch_reports_nothing() -> None:
    assert _names(StartupPosture(launch=_HARDENED, items=(_KNOWN,))) == []


@pytest.mark.parametrize(
    ("posture", "expected"),
    [
        (StartupPosture(launch=_PLAIN), ["interpreter_not_isolated"]),
        (StartupPosture(launch=_HARDENED, items=(_PLANTED,)), ["startup_code_unexpected"]),
        (StartupPosture(launch=_HARDENED, writable_site_dirs=("/v",)), ["site_packages_writable"]),
        (
            StartupPosture(launch=_HARDENED, unchecked_site_dirs=("/v",)),
            ["site_packages_unchecked"],
        ),
        (
            StartupPosture(
                launch=InterpreterLaunch(
                    True, True, True, True, code_path_variables=("PYTHONPATH",)
                )
            ),
            ["python_variables_reach_children"],
        ),
    ],
)
def test_each_deviation_has_its_own_name(posture: StartupPosture, expected: list[str]) -> None:
    assert _names(posture) == expected


def test_a_variable_the_engine_honours_is_named_in_the_not_isolated_entry() -> None:
    honoured = InterpreterLaunch(False, False, False, False, code_path_variables=("PYTHONPATH",))
    (risk,) = [r for n, r in startup_loosenings(StartupPosture(launch=honoured))]
    assert "PYTHONPATH is set in its environment now" in risk
    # CONTROL: under -E the same variable is not honoured, and the entry does not claim it is.
    ignored = InterpreterLaunch(False, False, True, False, code_path_variables=("PYTHONPATH",))
    (risk,) = [r for n, r in startup_loosenings(StartupPosture(launch=ignored))]
    assert "is set in its environment now" not in risk


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


def _child(tmp_path: Path, options: tuple[str, ...]) -> dict[str, object]:
    decoy = tmp_path / "decoy"
    (decoy / "messagefoundry").mkdir(parents=True, exist_ok=True)
    (decoy / "messagefoundry" / "__init__.py").write_text("raise SystemExit('DECOY')\n", "utf-8")
    env = {k: v for k, v in os.environ.items() if k.upper() != "PYTHON_DISABLE_REMOTE_DEBUG"}
    # The decoy is on PYTHONPATH AND is the working directory: an isolated child ignores both.
    env["PYTHONPATH"] = str(decoy)
    proc = subprocess.run(
        [sys.executable, *options, "-c", _CHILD_REPORT],
        capture_output=True,
        text=True,
        cwd=decoy,
        env=env,
        timeout=50,
    )
    return {"code": proc.returncode, "out": proc.stdout, "err": proc.stderr}


def test_the_isolated_launch_drops_both_entries_and_a_plain_one_has_both(tmp_path: Path) -> None:
    """The shipped launches pass :data:`ISOLATED_LAUNCH_OPTIONS`. With them, neither
    ``interpreter_not_isolated`` nor ``remote_debug_enabled`` is in the registry's list. The
    control is the same child without them, which also proves the decoy on PYTHONPATH would have
    won there: it exits before the report."""
    hardened = _child(tmp_path, ISOLATED_LAUNCH_OPTIONS)
    assert hardened["code"] == 0, hardened["err"]
    report = json.loads(str(hardened["out"]))
    assert report["isolated"] is True and report["safe_path"] is True
    assert "interpreter_not_isolated" not in report["names"]
    assert "remote_debug_enabled" not in report["names"]
    assert not any("decoy" in str(p) for p in report["path"])
    plain = _child(tmp_path, ())
    assert plain["code"] != 0 and "DECOY" in str(plain["err"]), (
        "CONTROL FAILED: the decoy on PYTHONPATH did not win in a plain child"
    )


def test_a_plain_child_reports_both_entries(tmp_path: Path) -> None:
    """The other half of the control, without the decoy in the way: an interpreter started with
    no options names both."""
    env = {k: v for k, v in os.environ.items() if k.upper() != "PYTHON_DISABLE_REMOTE_DEBUG"}
    env.pop("PYTHONPATH", None)
    proc = subprocess.run(
        [sys.executable, "-c", _CHILD_REPORT],
        capture_output=True,
        text=True,
        env=env,
        timeout=50,
    )
    assert proc.returncode == 0, proc.stderr
    names = json.loads(proc.stdout)["names"]
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
