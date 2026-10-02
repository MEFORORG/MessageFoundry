# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Each shipped service launch starts the interpreter isolated, with remote debugging off (vault
BACKLOG #2701, #2700).

The engine used to be started through its console-script launcher on both shipped launches: the
Windows installer registered ``messagefoundry.exe``, and the container image's entry point was
``messagefoundry``. A launcher cannot pass an option to the interpreter it starts. So the engine
honoured ``PYTHONPATH`` and ``PYTHONHOME``, and its remote-debugging interface was on. Both launches
now run ``python -I -X disable-remote-debug -m messagefoundry ...``.

What this file pins, and how:

1. **The options do what the launches rely on**, read off a real interpreter: the working
   directory is not on the import path under ``-m``, ``PYTHONPATH`` is ignored, and remote
   debugging is off. Each has the same child without the options beside it, where a decoy package
   in the working directory wins. The misspelt option is run too, because the interpreter accepts
   it and does nothing.
2. **The installer's launch line and the image's entry point carry them**, read from the two
   files. Each reader is also run over planted violations, where it must object.
3. **The image copies its venv root-owned.** The same reader, the same planted control.
4. **The two smoke legs read the result off the running engine.** That the steps are there, and
   judge the flags, is checked here; the legs' own results are the reading.
5. **The installer finds the interpreter beside the launcher or one folder up**, and nowhere else.
   ``Get-EngineInterpreter`` is lifted out of the script by PowerShell AST and run.

WHAT THIS DOES NOT TEST: that a registered Windows service or a built image starts. No test here
installs a service or builds an image. The ``windows-service-smoke`` and ``docker-smoke`` legs do.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from importlib import metadata
from pathlib import Path

import pytest

import messagefoundry
from messagefoundry.startupcode import ISOLATED_LAUNCH_OPTIONS

_ROOT = Path(__file__).resolve().parents[1]
_INSTALLER = _ROOT / "scripts" / "service" / "install-service.ps1"
_DOCKERFILE = _ROOT / "docker" / "Dockerfile"
_OPTIONS = " ".join(ISOLATED_LAUNCH_OPTIONS)

# --- 1. what the options do, on a real interpreter ---------------------------------------------


def _installed() -> bool:
    try:
        metadata.distribution("messagefoundry")
    except metadata.PackageNotFoundError:
        return False
    return True


_needs_install = pytest.mark.skipif(
    not _installed(),
    reason="SKIP (nothing run): messagefoundry is not an installed distribution here, so only the "
    "working directory could supply it, which is what isolated mode takes away",
)


def _decoy(tmp_path: Path) -> Path:
    """A working directory holding a package named like the engine, which refuses to import."""
    decoy = tmp_path / "decoy"
    (decoy / "messagefoundry").mkdir(parents=True)
    (decoy / "messagefoundry" / "__init__.py").write_text(
        "raise SystemExit('DECOY PACKAGE RAN')\n", encoding="utf-8"
    )
    return decoy


def _run(
    options: tuple[str, ...], *args: str, cwd: Path, **extra: str
) -> subprocess.CompletedProcess[str]:
    # The variables that would set, in the control arm, a flag the options are there to set.
    skip = {
        "PYTHONPATH",
        "PYTHONSAFEPATH",
        "PYTHONNOUSERSITE",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHON_DISABLE_REMOTE_DEBUG",
    }
    env = {k: v for k, v in os.environ.items() if k.upper() not in skip}
    env.update(extra)
    return subprocess.run(
        [sys.executable, *options, *args],
        capture_output=True,
        text=True,
        cwd=cwd,
        env=env,
        timeout=50,
    )


@_needs_install
def test_the_working_directory_is_not_on_the_import_path_of_the_shipped_launch(
    tmp_path: Path,
) -> None:
    """``python -m`` puts the working directory first on the import path. The shipped launch must
    not: the service's working directory is the repository on Windows and the store volume in the
    image. ``--version`` prints the package directory that answered."""
    decoy = _decoy(tmp_path)
    hardened = _run(ISOLATED_LAUNCH_OPTIONS, "-m", "messagefoundry", "--version", cwd=decoy)
    assert hardened.returncode == 0, hardened.stderr
    real = Path(messagefoundry.__file__).resolve().parent
    assert f"package: {real}" in hardened.stdout
    # CONTROL: the same command with no options runs the decoy.
    plain = _run((), "-m", "messagefoundry", "--version", cwd=decoy)
    assert plain.returncode != 0 and "DECOY PACKAGE RAN" in plain.stderr


_FLAGS = (
    "import sys; print(sys.flags.isolated, sys.flags.safe_path, sys.flags.ignore_environment, "
    "sys.flags.no_user_site, sys.is_remote_debug_enabled(), sys.flags.dont_write_bytecode)"
)


def test_the_options_isolate_the_interpreter_and_turn_remote_debugging_off(tmp_path: Path) -> None:
    hardened = _run(ISOLATED_LAUNCH_OPTIONS, "-c", _FLAGS, cwd=tmp_path)
    assert hardened.stdout.split() == ["1", "True", "1", "1", "False", "0"], hardened.stderr
    # CONTROL: none of that holds by default.
    plain = _run((), "-c", _FLAGS, cwd=tmp_path)
    assert plain.stdout.split()[:5] == ["0", "False", "0", "0", "True"], plain.stderr


def test_the_environment_variables_do_nothing_under_isolated_mode(tmp_path: Path) -> None:
    """Why the launches pass options and not variables. Under ``-I`` the interpreter ignores
    ``PYTHON_DISABLE_REMOTE_DEBUG``, ``PYTHONPATH`` and ``PYTHONDONTWRITEBYTECODE`` alike, so the
    image passes ``-B`` and both launches pass ``-X disable-remote-debug``."""
    variables = {
        "PYTHON_DISABLE_REMOTE_DEBUG": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": str(tmp_path),
    }
    probe = _FLAGS + "; print(sys.argv[1] in sys.path)"
    isolated = _run(("-I",), "-c", probe, str(tmp_path), cwd=tmp_path, **variables)
    assert isolated.stdout.split() == ["1", "True", "1", "1", "True", "0", "False"], isolated.stderr
    # CONTROL: without -I the same three variables are honoured.
    plain = _run((), "-c", probe, str(tmp_path), cwd=tmp_path, **variables)
    assert plain.stdout.split()[4:] == ["False", "1", "True"], plain.stderr


def test_the_underscore_spelling_of_the_option_is_accepted_and_ignored(tmp_path: Path) -> None:
    """The reason every reader below compares the exact spelling."""
    misspelt = _run(("-I", "-X", "disable_remote_debug"), "-c", _FLAGS, cwd=tmp_path)
    assert misspelt.returncode == 0, misspelt.stderr
    assert misspelt.stdout.split()[4] == "True"


def test_the_children_and_the_shipped_launches_spell_the_remote_debug_option_alike() -> None:
    """Two lists pass the option: the children's (``childenv``) and the shipped launches'. A
    misspelling in either is accepted by the interpreter, so they are held to one spelling here."""
    from messagefoundry.childenv import CHILD_INTERPRETER_FLAGS

    assert (
        CHILD_INTERPRETER_FLAGS[-2:]
        == ISOLATED_LAUNCH_OPTIONS[-2:]
        == ("-X", "disable-remote-debug")
    )


# --- 2 and 3. the two shipped launches, read from their files -----------------------------------


def installer_launch_problems(text: str) -> list[str]:
    """What is wrong with the service launch in ``install-service.ps1``, or nothing."""
    problems = []
    options = re.findall(r'^\$EngineInterpreterOptions = "([^"\n]*)"[ \t]*$', text, re.M)
    if options != [_OPTIONS]:
        problems.append(f"$EngineInterpreterOptions is {options}, not exactly [{_OPTIONS!r}]")
    params = re.findall(r'^\$AppParams = "([^\n]*)"[ \t]*$', text, re.M)
    if len(params) != 1 or not params[0].startswith(
        "$EngineInterpreterOptions -m messagefoundry serve "
    ):
        problems.append(
            f"$AppParams does not start with the options and -m messagefoundry: {params}"
        )
    for what, pattern in (
        ("the registered program", r"^Invoke-Nssm set \$ServiceName Application (\S+)[ \t]*$"),
        (
            "the program a new service is created with",
            r"^[ \t]*Invoke-Nssm install \$ServiceName (\S+)[ \t]*$",
        ),
    ):
        found = re.findall(pattern, text, re.M)
        if found != ["$PythonExe"]:
            problems.append(f"{what} is {found}, not the interpreter ($PythonExe)")
    return problems


_IMAGE_ENTRYPOINT = [
    "tini",
    "--",
    "/opt/venv/bin/python",
    *ISOLATED_LAUNCH_OPTIONS,
    "-u",
    "-B",
    "-m",
    "messagefoundry",
]


def image_problems(text: str) -> list[str]:
    """What is wrong with the image's entry point or the ownership of its venv, or nothing."""
    problems = []
    entrypoints = re.findall(r"^ENTRYPOINT (.*)$", text, re.M)
    parsed = []
    for raw in entrypoints:
        try:
            parsed.append(json.loads(raw))
        except json.JSONDecodeError:
            parsed.append(raw)  # shell form: never the exec list this expects
    if parsed != [_IMAGE_ENTRYPOINT]:
        problems.append(f"ENTRYPOINT is {parsed}, not exactly {[_IMAGE_ENTRYPOINT]}")
    copies = re.findall(r"^COPY (.*) /opt/venv /opt/venv[ \t]*$", text, re.M)
    if len(copies) != 2:
        problems.append(f"expected the venv to be copied in two final stages, found {len(copies)}")
    for flags in copies:
        owners = re.findall(r"--chown=(\S+)", flags)
        if owners != ["0:0"]:
            problems.append(f"a venv copy is owned by {owners or 'the default'}, not 0:0: {flags}")
    return problems


def test_the_installer_starts_the_interpreter_with_the_options() -> None:
    assert installer_launch_problems(_INSTALLER.read_text(encoding="utf-8")) == []


def test_the_image_starts_the_interpreter_with_the_options_and_owns_its_venv_as_root() -> None:
    assert image_problems(_DOCKERFILE.read_text(encoding="utf-8")) == []


@pytest.mark.parametrize(
    ("old", "new"),
    [
        # The option dropped, misspelt, or in the wrong case (-i is another option altogether).
        ('$EngineInterpreterOptions = "-I -X', '$EngineInterpreterOptions = "-X'),
        ('disable-remote-debug"\n', 'disable_remote_debug"\n'),
        ('$EngineInterpreterOptions = "-I ', '$EngineInterpreterOptions = "-i '),
        # The launch line no longer uses them.
        ('$AppParams = "$EngineInterpreterOptions -m messagefoundry serve', '$AppParams = "serve'),
        # The service runs the launcher again, which cannot pass them on.
        ("Application $PythonExe", "Application $AppExe"),
        ("Invoke-Nssm install $ServiceName $PythonExe", "Invoke-Nssm install $ServiceName $AppExe"),
    ],
)
def test_the_installer_reader_objects_to_a_planted_violation(old: str, new: str) -> None:
    text = _INSTALLER.read_text(encoding="utf-8")
    assert text.count(old) == 1, f"CONTROL FAILED: {old!r} is not in the installer exactly once"
    assert installer_launch_problems(text.replace(old, new)), f"planting {new!r} was not noticed"


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ('"/opt/venv/bin/python", "-I", "-X", "disable-remote-debug", "-u", "-B", "-m", ', ""),
        ('"-I", ', ""),
        ('"disable-remote-debug"', '"disable_remote_debug"'),
        ('"-u", "-B", ', ""),
        ('"/opt/venv/bin/python"', '"python"'),
        ("COPY --from=builder --chown=0:0", "COPY --from=builder --chown=10001:10001"),
        ("COPY --from=builder-sqlserver --chown=0:0", "COPY --from=builder-sqlserver"),
    ],
)
def test_the_image_reader_objects_to_a_planted_violation(old: str, new: str) -> None:
    text = _DOCKERFILE.read_text(encoding="utf-8")
    assert text.count(old) == 1, f"CONTROL FAILED: {old!r} is not in the Dockerfile exactly once"
    assert image_problems(text.replace(old, new)), f"planting {new!r} was not noticed"


# --- 4. the smoke legs read the result off the running engine -----------------------------------


def _step_script(job: str, name_starts: str) -> tuple[int, str]:
    """One ``ci.yml`` step's position and comment-free run script. Imported here: without PyYAML
    that module skips whoever imports it."""
    from tests._workflow_contexts import step_script

    return step_script("ci.yml", job, name_starts)


def test_the_windows_smoke_leg_reads_the_launch_off_the_running_service() -> None:
    """THIS CANNOT BE DEMONSTRATED FROM A PULL REQUEST: the job runs on a schedule, on dispatch and
    in the merge queue."""
    at, script = _step_script("windows-service-smoke", "Verify the service runs isolated")
    for needle in (
        f'$options = "{_OPTIONS}"',
        '$tail = " -m messagefoundry serve "',
        "$registered.AppParameters -cnotmatch $launch",
        '"https://127.0.0.1:8765/security/posture"',
        "$interpreter.isolated -ne $true",
        "$interpreter.safe_path -ne $true",
        "$interpreter.ignore_environment -ne $true",
        "$interpreter.remote_debug_enabled -ne $false",
        '"interpreter_not_isolated", "remote_debug_enabled"',
    ):
        assert needle in script, f"the step no longer has {needle!r}"
    # Case-sensitive throughout: -i is a different interpreter option from -I.
    assert not re.search(r"-(not)?match\b", script), "a launch comparison ignores case"
    assert "CONTROL FAILED" in script
    # It must read the ENGINE: the token step after it puts a probe in the engine's place.
    token, token_script = _step_script(
        "windows-service-smoke", "Verify the service token is restricted"
    )
    assert at < token, "the launch is read after the token step has replaced the engine"
    # That step saves the engine's parameters and checks they are the engine's before it goes on.
    assert f"-cnotmatch '^{_OPTIONS} -m messagefoundry serve '" in token_script


def test_the_image_smoke_leg_reads_the_launch_and_tries_the_write() -> None:
    _, script = _step_script("docker-smoke", "Verify the engine runs isolated")
    wanted = " ".join(_IMAGE_ENTRYPOINT[2:]) + " serve "
    for needle in (
        f'wanted="{wanted}"',
        "/proc/1/cmdline",
        "https://127.0.0.1:8765/security/posture",
        'for flag in ("isolated", "safe_path", "ignore_environment"):',
        'interpreter["remote_debug_enabled"] is not False',
        'interpreter["writable_site_dirs"]',
        "docker exec mefor touch /var/lib/mefor/write-control",
        'if docker exec mefor touch "$site/planted-by-smoke.pth"; then',
    ):
        assert needle in script, f"the step no longer has {needle!r}"
    assert script.count("CONTROL FAILED") >= 2


# --- 5. the installer finds the interpreter ------------------------------------------------------


def test_the_installer_finds_the_interpreter_beside_the_launcher_or_one_folder_up(
    tmp_path: Path,
) -> None:
    """A virtual environment keeps both in one Scripts folder; a system-wide install keeps the
    interpreter one folder up. Anything else finds nothing, and the installer then refuses."""
    from tests.test_service_install_manifest import _extract, _ok, _psq

    venv = tmp_path / "venv" / "Scripts"
    system = tmp_path / "system" / "Scripts"
    user = tmp_path / "user" / "Scripts"
    for scripts in (venv, system, user):
        scripts.mkdir(parents=True)
        (scripts / "messagefoundry.exe").write_bytes(b"")
    (venv / "python.exe").write_bytes(b"")
    (venv.parent / "python.exe").write_bytes(b"")  # beside wins over one folder up
    (system.parent / "python.exe").write_bytes(b"")
    (user.parent / "python.exe").mkdir()  # a folder of that name is not an interpreter
    body = (
        "  [pscustomobject]@{\n"
        + "".join(
            f"    {key} = (Get-EngineInterpreter -AppExe {_psq(str(scripts / 'messagefoundry.exe'))})\n"
            for key, scripts in (("venv", venv), ("system", system), ("user", user))
        )
        + "  } | ConvertTo-Json -Compress\n"
    )
    got = json.loads(
        _ok(_extract(_INSTALLER, ["Get-EngineInterpreter"], body), tmp_path)
        .strip()
        .splitlines()[-1]
    )
    assert got == {
        "venv": str(venv / "python.exe"),
        "system": str(system.parent / "python.exe"),
        "user": "",
    }


def test_the_installer_refuses_when_no_interpreter_is_found() -> None:
    """Static, because the refusal sits in the script body, which no test runs. Without it an empty
    path would be registered as the service's program."""
    text = _INSTALLER.read_text(encoding="utf-8")
    refusal = text.index(
        "if (-not $PythonExe -or -not (Test-Path -LiteralPath $PythonExe -PathType Leaf))"
    )
    assert "throw" in text[refusal : refusal + 400]
    assert refusal < text.index("Invoke-Nssm install $ServiceName $PythonExe")
