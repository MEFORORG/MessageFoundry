# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every child process the engine starts gets an environment somebody chose (vault BACKLOG #2587).

Three things are pinned here.

* **Behaviour, through the real spawn.** A Handler run by a real :class:`SandboxSession` reports
  what its own process environment holds. A DR hook run by the real ``_run_command`` writes its
  environment to a file. Each has a control that must give the opposite answer, so neither can pass
  by seeing nothing at all.
* **The builders, against the suite's registry of secret names.** ``CRITICAL_SECRETS`` in
  ``tests/test_secret_rotation_inventory.py`` is held complete against the code by that file's own
  tests, so a secret variable added to the engine is checked here without anyone editing this file.
* **A static guard.** Every process-starting call in the shipped packages passes ``env=``, or is
  named in :data:`_INHERITS_ON_PURPOSE` with its reason.

Values are marker strings, never keys. Synthetic HL7 only.
"""

from __future__ import annotations

import ast
import asyncio
import functools
import os
import shutil
import site
import subprocess
import sys
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

import messagefoundry
from messagefoundry import _child_bootstrap, childenv
from messagefoundry.config import settings
from messagefoundry.config.environments import VALUE_ENV_PREFIX
from messagefoundry.config.run_context import RunContext
from messagefoundry.config.wiring import Registry, load_config
from messagefoundry.pipeline import dr, supervisor
from messagefoundry.pipeline import sandbox as sandbox_mod
from messagefoundry.pipeline.dryrun import transform_one
from tests.test_dangerous_functionality_doc import (
    _ARGV,
    _ATTRIBUTE_STARTS,
    _CONSOLE,
    _OS_EXEC_RE,
    _SHELL,
    _START_FORMS,
    _SUBPROCESS_FUNCS,
    _aliases,
    _annotation_nodes,
    _dotted,
    _package_sources,
    _python_under,
    _start_sites,
)
from tests.test_sandbox import RAW, _session
from tests.test_secret_rotation_inventory import CRITICAL_SECRETS

_MARKER = "marker-not-a-key"
#: A name in no allowlist and in no engine namespace: the worker must not get it either, which is
#: what shows the worker's environment is a list of what is let in and not a list of what is kept out.
_ORDINARY = "ORDINARY_OPERATOR_VARIABLE"
#: The control. An interpreter variable is on the worker's allowlist, and this one changes nothing a
#: Handler in this file observes.
_ALLOWED = "PYTHONHASHSEED"
_ALLOWED_VALUE = "4242"

#: The secrets a library reads when the engine's own setting is unset. Typed here, not read from
#: ``childenv``: a list checked against itself checks nothing.
_LIBRARY_FALLBACK_SECRETS = frozenset({"VAULT_TOKEN", "PGPASSWORD"})

#: Every environment name the engine calls a secret: the registry's fixed names, one ``env()``
#: connection secret (the prefix is fixed, the suffix is the operator's), and the names outside
#: the engine's namespace that it may still rely on.
_SECRET_NAMES = frozenset(
    {name for name in CRITICAL_SECRETS if name.startswith(childenv.ENGINE_ENV_PREFIX)}
    | {VALUE_ENV_PREFIX + "PARTNER_PASSWORD"}
    | _LIBRARY_FALLBACK_SECRETS
)


def test_the_secret_names_are_a_real_list() -> None:
    """The oracle the other tests iterate. Empty, every one of them would pass having checked nothing."""
    assert settings.STORE_DEK_SECRET_CLASS in _SECRET_NAMES
    assert len(_SECRET_NAMES) >= 10
    assert childenv.ENGINE_ENV_PREFIX == settings._ENV_PREFIX


# --- the sandbox worker, through the real spawn -------------------------------------------------

_GRAPH = """
import os
import sys

import messagefoundry
from messagefoundry import inbound, outbound, router, handler, MLLP, Send

inbound("IB_ENV", MLLP(port=19431), router="r")
outbound("OB_ENV", MLLP(host="127.0.0.1", port=19432))

NAMES = __NAMES__


@router("r")
def r(msg):
    return "h_report"


@handler("h_report")
def h_report(msg):
    seen = ";".join(n + "=" + os.environ.get(n, "ABSENT") for n in NAMES)
    return Send("OB_ENV", seen + ";PID=" + str(os.getpid()))


@handler("h_path")
def h_path(msg):
    try:
        import mf_child_env_cwd_marker  # noqa: F401

        marker = "IMPORTED"
    except ImportError:
        marker = "NOT-IMPORTABLE"
    import sysconfig

    def where(directory):
        wanted = os.path.normcase(os.path.abspath(directory))
        found = [i for i, e in enumerate(sys.path) if e and os.path.normcase(os.path.abspath(e)) == wanted]
        return found[0] if found else -1

    package_root = os.path.dirname(os.path.dirname(os.path.abspath(messagefoundry.__file__)))
    return Send(
        "OB_ENV",
        "SAFE=" + str(sys.flags.safe_path) + ";MARKER=" + marker + ";MF=" + messagefoundry.__file__
        + ";STDLIB=" + str(where(sysconfig.get_path("stdlib"))) + ";ROOT=" + str(where(package_root))
        + ";REMOTE_DEBUG=" + str(sys.is_remote_debug_enabled()),
    )
"""


@pytest.fixture
def graph(tmp_path: Path) -> tuple[Registry, str]:
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    names = [*sorted(_SECRET_NAMES), _ORDINARY, _ALLOWED]
    (config_dir / "graph.py").write_text(_GRAPH.replace("__NAMES__", repr(names)), encoding="utf-8")
    return load_config(config_dir), str(config_dir)


def _run(registry: Registry, config_dir: str, handler_name: str) -> dict[str, str]:
    session = _session(config_dir, inbound="IB_ENV")
    try:
        deliveries, _, _, _ = transform_one(
            registry, handler_name, RAW, sandbox=session, run_context=RunContext()
        )
    finally:
        session.close()
    assert len(deliveries) == 1, deliveries
    return dict(part.split("=", 1) for part in deliveries[0].payload.split(";"))


def test_a_sandboxed_handler_is_not_handed_the_engines_secret_variables(
    graph: tuple[Registry, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    registry, config_dir = graph
    for name in (*_SECRET_NAMES, _ORDINARY):
        monkeypatch.setenv(name, _MARKER)
    monkeypatch.setenv(_ALLOWED, _ALLOWED_VALUE)

    seen = _run(registry, config_dir, "h_report")

    # Controls first: the Handler really ran in another process, and a variable on the allowlist
    # really crossed. Without both, "absent" below could mean "nothing was read".
    assert seen.pop("PID") != str(os.getpid())
    assert seen.pop(_ALLOWED) == _ALLOWED_VALUE
    assert seen.pop(_ORDINARY) == "ABSENT"
    assert set(seen) == _SECRET_NAMES
    assert {name: value for name, value in seen.items() if value != "ABSENT"} == {}


def test_the_worker_does_not_search_the_working_directory_and_loads_the_parents_build(
    graph: tuple[Registry, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry, config_dir = graph
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    (cwd / "mf_child_env_cwd_marker.py").write_text("MARKER = 1\n", encoding="utf-8")
    monkeypatch.chdir(cwd)

    seen = _run(registry, config_dir, "h_path")

    assert seen["SAFE"] == "True"
    assert seen["MARKER"] == "NOT-IMPORTABLE"
    assert Path(seen["MF"]).resolve() == Path(messagefoundry.__file__).resolve()
    # The package's directory is on the worker's path, and the standard library is searched first.
    assert 0 <= int(seen["STDLIB"]) < int(seen["ROOT"])
    assert seen["REMOTE_DEBUG"] == "False"


def test_the_sandbox_hands_its_worker_one_engine_switch_and_no_other_engine_variable(
    graph: tuple[Registry, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The worker runs ``load_config`` itself, so the parent's answer on the config-source gate has
    to reach it, or it would refuse a directory its parent loaded. Read off the real spawn call."""
    _registry, config_dir = graph
    captured: dict[str, Any] = {}

    class _Stop(Exception):
        pass

    def fake_popen(argv: list[str], **kwargs: Any) -> None:
        captured["argv"] = argv
        captured["env"] = kwargs["env"]
        raise _Stop

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    for name in (settings.INSECURE_CONFIG_SOURCE_ESCAPE_ENV, settings.INSECURE_TLS_ESCAPE_ENV):
        monkeypatch.setenv(name, "1")
    for name in _SECRET_NAMES:
        monkeypatch.setenv(name, _MARKER)

    with pytest.raises(_Stop):
        _session(config_dir, inbound="IB_ENV")._spawn()

    engine_names = {n for n in captured["env"] if n.startswith(childenv.ENGINE_ENV_PREFIX)}
    assert engine_names == {settings.INSECURE_CONFIG_SOURCE_ESCAPE_ENV}
    assert captured["argv"] == childenv.python_child_argv(sandbox_mod.WORKER_MODULE)


# --- the DR hook, through the real spawn --------------------------------------------------------


def _dump_environment_command(target: Path) -> str:
    """A shell command that writes its own environment to ``target``, one ``NAME=value`` per line."""
    if sys.platform == "win32":
        return f'set > "{target}"'
    return f"env > '{target}'"


@pytest.mark.asyncio
async def test_a_dr_hook_keeps_ordinary_variables_and_gets_none_of_the_engines(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in (*_SECRET_NAMES, _ORDINARY):
        monkeypatch.setenv(name, _MARKER)
    target = tmp_path / "hook-environment.txt"

    assert await dr._run_command(_dump_environment_command(target)) is True

    lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    seen = {line.split("=", 1)[0].upper() for line in lines if "=" in line}
    # Control: an operator's own variable reaches the hook, so the file is a real environment dump.
    assert _ORDINARY in seen
    assert "PATH" in seen
    assert seen & _SECRET_NAMES == set()
    assert [name for name in seen if name.startswith(childenv.ENGINE_ENV_PREFIX)] == []


# --- the builders -------------------------------------------------------------------------------


def _parent_environment() -> dict[str, str]:
    env = dict.fromkeys(_SECRET_NAMES, _MARKER)
    env.update(
        {
            "PATH": "/usr/bin",
            "TZ": "UTC",
            _ORDINARY: _MARKER,
            _ALLOWED: _ALLOWED_VALUE,
            settings.INSECURE_CONFIG_SOURCE_ESCAPE_ENV: "1",
            settings.INSECURE_TLS_ESCAPE_ENV: "1",
        }
    )
    return env


def test_the_worker_environment_is_an_allowlist() -> None:
    parent = _parent_environment()
    env = childenv.worker_environment(parent)
    kept = {name: env[name] for name in parent if name in env}
    assert kept == {"PATH": "/usr/bin", "TZ": "UTC", _ALLOWED: _ALLOWED_VALUE}


def test_a_variable_that_only_looks_like_the_interpreters_or_the_locales_does_not_cross() -> None:
    """The allowlist is names, not prefixes: an operator's own variable can start with the same
    letters as an interpreter or a locale variable."""
    parent = {"PYTHON_APP_SECRET": _MARKER, "PYTHONSTARTUP": "x", "LC_MY_TOKEN": _MARKER}
    assert childenv.worker_environment({**parent, "PYTHONUTF8": "1"}).get("PYTHONUTF8") == "1"
    assert set(childenv.worker_environment(parent)) & set(parent) == set()


def test_an_extra_name_crosses_and_nothing_else_in_the_engine_namespace_does() -> None:
    switch = settings.INSECURE_CONFIG_SOURCE_ESCAPE_ENV
    env = childenv.worker_environment(_parent_environment(), extra_names=(switch,))
    assert {n for n in env if n.startswith(childenv.ENGINE_ENV_PREFIX)} == {switch}
    with pytest.raises(TypeError):
        childenv.worker_environment(_parent_environment(), extra_names=switch)


def test_the_operator_page_names_each_library_secret_the_hook_loses() -> None:
    """The ``[dr]`` rows state the rule in words an operator reads. Hold them to the code's list."""
    repository = Path(__file__).resolve().parents[1]
    page = (repository / "docs" / "CONFIGURATION.md").read_text(encoding="utf-8")
    row = next(line for line in page.splitlines() if line.startswith("| `takeover_hook` |"))
    assert childenv.ENGINE_SECRETS_OUTSIDE_THE_PREFIX == _LIBRARY_FALLBACK_SECRETS
    assert [name for name in sorted(_LIBRARY_FALLBACK_SECRETS) if f"`{name}`" not in row] == []


def test_the_hook_environment_drops_the_engine_namespace_and_nothing_else() -> None:
    parent = _parent_environment()
    env = childenv.hook_environment(parent)
    dropped = set(parent) - set(env)
    assert dropped == {
        n
        for n in parent
        if n.startswith(childenv.ENGINE_ENV_PREFIX) or n in _LIBRARY_FALLBACK_SECRETS
    }
    assert dropped >= _SECRET_NAMES
    assert env[_ORDINARY] == _MARKER


def test_the_hook_environment_ignores_the_case_of_the_engine_prefix() -> None:
    """Windows treats a variable's name as case-insensitive, so the lower-case spelling is the same
    variable there."""
    assert childenv.hook_environment({"mefor_store_password": _MARKER, "Path": "x"}) == {
        "Path": "x"
    }


def test_an_engine_shard_keeps_every_variable() -> None:
    """A shard is a whole engine. It opens the store and builds connections, so it needs the secrets."""
    parent = _parent_environment()
    env = childenv.engine_environment(parent)
    assert {name: env[name] for name in parent} == parent


@pytest.mark.asyncio
async def test_the_supervisor_starts_a_shard_with_that_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    async def fake_exec(*argv: str, **kwargs: Any) -> object:
        captured.update(kwargs)
        return object()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setenv(settings.STORE_DEK_SECRET_CLASS, _MARKER)
    spec = supervisor.ShardSpec(shard="a", db_path="a.db", port=1, argv=("python", "a"))

    await supervisor._default_spawn(spec)

    assert captured["env"][settings.STORE_DEK_SECRET_CLASS] == _MARKER
    assert captured["env"] == childenv.engine_environment()


#: An absolute directory, for an operator's own ``PYTHONPATH`` entry.
_OPERATOR_PATH = str(Path(__file__).resolve().parent / "operator-libraries")

_BUILDERS_OF_A_PYTHON_CHILD = (childenv.worker_environment, childenv.engine_environment)


@pytest.mark.parametrize(
    "inherited",
    ["", ".", os.pathsep + _OPERATOR_PATH, _OPERATOR_PATH + os.pathsep, "relative-directory"],
)
def test_an_entry_that_names_the_working_directory_does_not_reach_the_child(inherited: str) -> None:
    """An empty or relative ``PYTHONPATH`` entry resolves against the working directory, which the
    child's script start keeps off its path, so it must not cross. An absolute entry crosses, and
    nothing is added: the child is told where the package is by its bootstrap, never through
    ``PYTHONPATH``."""
    expected = [_OPERATOR_PATH] if _OPERATOR_PATH in inherited else []
    for build in _BUILDERS_OF_A_PYTHON_CHILD:
        crossed = build({"PYTHONPATH": inherited}).get("PYTHONPATH", "")
        assert [entry for entry in crossed.split(os.pathsep) if entry] == expected
        assert "PYTHONPATH" not in build({})


def test_a_python_child_starts_with_the_interpreters_remote_debugging_disabled() -> None:
    """Read off real interpreters. The control is a child started without the flags: it must report
    remote debugging ENABLED, or "disabled" below would not show that the flags did it. That also
    catches a spelling the interpreter accepts and ignores."""
    probe = "import sys; print(sys.flags.safe_path, sys.is_remote_debug_enabled())"

    def answer(flags: tuple[str, ...]) -> str:
        done = subprocess.run(  # noqa: S603 - this interpreter, a fixed command line
            [sys.executable, *flags, "-c", probe],
            env=childenv.worker_environment(),
            capture_output=True,
            text=True,
            timeout=60,
            check=True,
        )
        return done.stdout.strip()

    if answer(()) != "False True":
        pytest.skip("this interpreter starts with remote debugging already off")
    flags = childenv.CHILD_INTERPRETER_FLAGS
    assert answer(flags) == "True False"
    assert childenv.python_child_argv("a.module")[1 : 1 + len(flags)] == list(flags)


def test_the_bootstrap_runs_a_module_with_its_arguments_and_without_the_working_directory(
    tmp_path: Path,
) -> None:
    """Through a real interpreter, the way an engine shard starts: the module runs as ``__main__``,
    its argument arrives, and a decoy package of the same name does not answer in place of this
    build. The decoy is in the working directory AND on an absolute ``PYTHONPATH`` entry, which the
    interpreter searches ahead of everything the bootstrap can add."""
    decoy = tmp_path / "messagefoundry"
    decoy.mkdir()
    (decoy / "__init__.py").write_text("raise SystemExit('the decoy answered')\n", encoding="utf-8")
    (decoy / "__main__.py").write_text("raise SystemExit('the decoy answered')\n", encoding="utf-8")
    done = subprocess.run(  # noqa: S603 - this interpreter, a fixed command line
        [*childenv.python_child_argv("messagefoundry"), "--version"],
        cwd=tmp_path,
        env=childenv.engine_environment({**os.environ, "PYTHONPATH": str(tmp_path)}),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    assert f"package: {Path(messagefoundry.__file__).resolve().parent}" in done.stdout


#: ``base`` is the interpreter's base prefix in the placement test below; the standard library's
#: entries sit inside it.
_VENV_SITES = ["site"]
_NO_VENV_WINDOWS_SITES = ["base", "base/Lib/site-packages"]


@pytest.mark.parametrize(
    ("sites", "path", "expected"),
    [
        # Not on the path: it goes after the standard library and ahead of site-packages.
        (
            _VENV_SITES,
            ["base/zip", "base/Lib", "site", "user-site"],
            ["base/zip", "base/Lib", "ROOT", "site", "user-site"],
        ),
        # No site-packages on the path at all: last.
        (_VENV_SITES, ["base/zip", "base/Lib"], ["base/zip", "base/Lib", "ROOT"]),
        # Already there, which is the installed case: untouched.
        (
            _VENV_SITES,
            ["base/zip", "base/Lib", "site", "ROOT"],
            ["base/zip", "base/Lib", "site", "ROOT"],
        ),
        # PYTHONPATH named site-packages, so it sits ahead of the standard library. The directory
        # still goes after the standard library (vault BACKLOG #2800).
        (
            _VENV_SITES,
            ["site", "base/zip", "base/Lib", "user-site"],
            ["site", "base/zip", "base/Lib", "ROOT", "user-site"],
        ),
        # The same, with no site-packages directory left after the standard library: last.
        (_VENV_SITES, ["site", "base/zip", "base/Lib"], ["site", "base/zip", "base/Lib", "ROOT"]),
        # An operator's own PYTHONPATH entry ahead of the standard library changes nothing.
        (
            _VENV_SITES,
            ["operator", "base/zip", "base/Lib", "site"],
            ["operator", "base/zip", "base/Lib", "ROOT", "site"],
        ),
        # Windows without a virtual environment: the base prefix is a site directory, and an
        # entry a .pth file adds inside site-packages is not the standard library.
        (
            _NO_VENV_WINDOWS_SITES,
            ["base/zip", "base/Lib", "base", "base/Lib/site-packages", "base/Lib/site-packages/w"],
            [
                "base/zip",
                "base/Lib",
                "ROOT",
                "base",
                "base/Lib/site-packages",
                "base/Lib/site-packages/w",
            ],
        ),
        # The same, with site-packages named on PYTHONPATH.
        (
            _NO_VENV_WINDOWS_SITES,
            ["base/Lib/site-packages", "base/zip", "base/Lib", "base"],
            ["base/Lib/site-packages", "base/zip", "base/Lib", "ROOT", "base"],
        ),
    ],
)
def test_where_the_bootstrap_puts_the_package_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    sites: list[str],
    path: list[str],
    expected: list[str],
) -> None:
    """The placement itself. An editable install already has the directory on the path, so a real
    child in this suite never takes the inserting branch."""
    root = str(Path(messagefoundry.__file__).resolve().parent.parent)

    def real(names: list[str]) -> list[str]:
        return [root if name == "ROOT" else str(tmp_path / name) for name in names]

    monkeypatch.setattr(sys, "base_prefix", str(tmp_path / "base"))
    monkeypatch.setattr(sys, "base_exec_prefix", str(tmp_path / "base"))
    monkeypatch.setattr(site, "getsitepackages", lambda: real(sites))
    monkeypatch.setattr(site, "getusersitepackages", lambda: real(["user-site"])[0])
    monkeypatch.setattr(sys, "path", real(path))
    _child_bootstrap._place_package_root()
    assert sys.path == real(expected)


def test_a_site_packages_directory_on_pythonpath_does_not_let_the_checkout_shadow_the_stdlib(
    tmp_path: Path,
) -> None:
    """Through a real interpreter (vault BACKLOG #2800). A copy of the bootstrap sits in a checkout
    that is not on the path, beside a decoy ``json.py``. ``PYTHONPATH`` names a real site-packages
    directory, which the interpreter puts ahead of the standard library. The child must still import
    the standard library's ``json``. The control is a marker module beside the decoy: it must
    import, or the decoy's absence would only show the checkout was never on the path."""
    checkout = tmp_path / "checkout"
    package = checkout / "messagefoundry"
    package.mkdir(parents=True)
    shutil.copyfile(_child_bootstrap.__file__, package / "_child_bootstrap.py")
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "probe.py").write_text(
        "import json\nimport mf_checkout_marker\nprint(json.__file__)\n", encoding="utf-8"
    )
    (checkout / "json.py").write_text("raise SystemExit('the decoy answered')\n", encoding="utf-8")
    (checkout / "mf_checkout_marker.py").write_text("", encoding="utf-8")
    site_packages = site.getsitepackages()[-1]

    done = subprocess.run(  # noqa: S603 - this interpreter, a fixed command line
        [
            sys.executable,
            *childenv.CHILD_INTERPRETER_FLAGS,
            str(package / "_child_bootstrap.py"),
            "messagefoundry.probe",
        ],
        cwd=tmp_path,
        env=childenv.engine_environment({**os.environ, "PYTHONPATH": site_packages}),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    assert Path(done.stdout.strip()).resolve().parent != checkout.resolve()


# --- the static guard ---------------------------------------------------------------------------
#
# The names that start a process, the alias resolution and the engine tree are the process-start
# inventory's own (tests/test_dangerous_functionality_doc.py), imported so the two cannot disagree
# about which names start a process. That inventory asks which MODULES start a process and in what
# form. This guard asks a different question of each start: where does the child's environment come
# from. The walk over calls is this file's own.
#
# Its limits, so nobody reads a green run as more than it is. It reads at least the starts the
# inventory's tables name. It takes ``env=<name>`` on trust when that name is bound once, in the
# same function body, straight from a builder; it does not see the dict being changed afterwards
# (``env.update(...)``). It cannot see a start made by a third-party library, or one reached
# through ``getattr`` with a computed name.

#: The only environments that count as chosen: a call to one of these.
_BUILDERS = frozenset(
    f"messagefoundry.childenv.{name}"
    for name in ("worker_environment", "hook_environment", "engine_environment")
)

_PINNED_TOOL = (
    "runs one fixed Windows system tool by its absolute System32 path, with an argument list and no "
    "shell; it executes nothing an operator or a config author wrote"
)
_TRAY_OPENS_FOR_ITS_USER = (
    "the tray is the desktop user's own process, not the engine service; it opens a file, a folder "
    "or a page in that user's own program, which needs the user's environment"
)
_SERVICE_CONTROL = (
    "an elevated service-control or install command a desktop administrator asked for from the "
    "tray or the CLI; ShellExecute takes no environment argument, and the command line is built "
    "from validated names only"
)
_AS_A_VALUE = " (as a value)"

#: Starts that hand the child the caller's whole environment on purpose, as ``(module, enclosing
#: function, start)``, each with its reason. A start named ``... (as a value)`` is a reference to
#: the function that is not itself a call. An entry covers ONE start unless :data:`_MORE_THAN_ONE`
#: says otherwise: a second start added to a listed function fails the guard.
_INHERITS_ON_PURPOSE: dict[tuple[str, str, str], str] = {
    ("auth/trust_anchors.py", "dacl_is_owner_only", "subprocess.run"): _PINNED_TOOL,
    ("store/store.py", "_secure_file", "subprocess.run"): _PINNED_TOOL,
    ("store/store.py", "_grant_read", "subprocess.run"): _PINNED_TOOL,
    ("service.py", "service_state", "subprocess.run"): _PINNED_TOOL,
    ("service.py", "control_service", "ShellExecuteW"): _SERVICE_CONTROL,
    ("service.py", "_runas_wait", "ShellExecuteExW"): _SERVICE_CONTROL,
    ("service.py", "_runas_wait", "ShellExecuteExW" + _AS_A_VALUE): (
        "sets the ctypes prototype of the call listed on the line above; it starts nothing"
    ),
    ("service.py", "install_service", "ShellExecuteW"): _SERVICE_CONTROL,
    ("service_status.py", "_query", "subprocess.run"): _PINNED_TOOL,
    ("checks.py", "_run_tool", "subprocess.run"): (
        "the developer's own `messagefoundry check` command, run by hand or in CI and never by the "
        "service; ruff and mypy read their settings from the developer's environment, so it passes "
        "all of it plus one variable"
    ),
    ("tray/actions.py", "_run_detached", "subprocess.Popen"): _TRAY_OPENS_FOR_ITS_USER,
    ("tray/actions.py", "_open_path", "os.startfile"): _TRAY_OPENS_FOR_ITS_USER,
    ("tray/actions.py", "_open_path", "webbrowser.open"): _TRAY_OPENS_FOR_ITS_USER,
    ("tray/actions.py", "open_console", "webbrowser.open" + _AS_A_VALUE): _TRAY_OPENS_FOR_ITS_USER,
    ("tray/app.py", "TrayApp._edit_settings", "os.startfile"): _TRAY_OPENS_FOR_ITS_USER,
    ("tray/branding.py", "relaunch_branded", "subprocess.Popen"): (
        "the tray starting itself again under its branded launcher: the same program, as the same "
        "desktop user, so it needs the environment it already has"
    ),
}

#: Listed sites that hold more than one start, with the number.
_MORE_THAN_ONE: dict[tuple[str, str, str], int] = {
    # The prototype is set in two statements: ``argtypes`` and ``restype``.
    ("service.py", "_runas_wait", "ShellExecuteExW" + _AS_A_VALUE): 2,
}

#: The sites this change is about. They are also the positive control: a walker that could not see
#: a call would report a clean tree, so each of these must be seen, and seen with a chosen environment.
_MUST_CHOOSE = frozenset(
    {
        ("pipeline/sandbox.py", "SandboxSession._spawn", "subprocess.Popen"),
        ("pipeline/dr.py", "_run_command", "create_subprocess_shell"),
        ("pipeline/supervisor.py", "_default_spawn", "create_subprocess_exec"),
        ("pipeline/supervisor.py", "preflight_shard_config", "create_subprocess_exec"),
    }
)

_Site = tuple[str, str, str]


def _start_name(expr: ast.expr, aliases: Mapping[str, str]) -> tuple[str, bool] | None:
    """``(the process start an expression names, whether that start accepts env=)``, or ``None``."""
    dotted = _dotted(expr, aliases)
    if dotted in _SUBPROCESS_FUNCS:
        return dotted, True
    last = expr.attr if isinstance(expr, ast.Attribute) else (dotted or "").rpartition(".")[2]
    for pattern, form in _ATTRIBUTE_STARTS:
        if last and pattern.match(last):
            # Among the starts matched by name alone, the asyncio ones are the shell and
            # argument-list forms, and they take env=. ShellExecute and CreateProcess do not.
            return last, form in (_SHELL, _ARGV)
    if dotted is not None and (dotted in _START_FORMS or _OS_EXEC_RE.match(dotted)):
        return dotted, False
    return None


def _is_builder_call(node: ast.AST, aliases: Mapping[str, str]) -> bool:
    return isinstance(node, ast.Call) and _dotted(node.func, aliases) in _BUILDERS


def _own_nodes(scope: ast.AST) -> list[ast.AST]:
    """The nodes of one function or module body, without the bodies of the functions, lambdas and
    classes nested in it: a name bound in an inner scope says nothing about the outer one."""
    found: list[ast.AST] = []
    pending = list(ast.iter_child_nodes(scope))
    while pending:
        node = pending.pop()
        found.append(node)
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda | ast.ClassDef):
            pending.extend(ast.iter_child_nodes(node))
    return found


def _built_names(scope: ast.AST, aliases: Mapping[str, str]) -> frozenset[str]:
    """The local names ``scope`` binds exactly once, and binds straight from a builder call. A
    parameter, or a name bound a second time, is not one of them."""
    nodes = _own_nodes(scope)
    bound = Counter(
        node.id for node in nodes if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
    )
    bound.update(node.arg for node in nodes if isinstance(node, ast.arg))
    return frozenset(
        target.id
        for node in nodes
        if isinstance(node, ast.Assign) and _is_builder_call(node.value, aliases)
        for target in node.targets
        if isinstance(target, ast.Name) and bound[target.id] == 1
    )


def _chooses_an_environment(
    call: ast.Call, aliases: Mapping[str, str], built: frozenset[str]
) -> bool:
    """Whether ``env=`` is a builder's result. Anything else is the caller's environment or might
    be: no ``env=``, ``env=None``, ``os.environ`` or a copy of it, a dict built by hand, ``**kwargs``."""
    for keyword in call.keywords:
        if keyword.arg == "env":
            value = keyword.value
            return _is_builder_call(value, aliases) or (
                isinstance(value, ast.Name) and value.id in built
            )
    return False


def _spawn_sites(sources: Mapping[str, str]) -> tuple[Counter[_Site], Counter[_Site]]:
    """Every process start in ``sources``, counted per site: ``(starts whose environment a builder
    chose, starts that hand over the caller's)``. A site is ``(module, enclosing function, start)``,
    and the function is qualified by its classes, so two methods of one name stay apart. A start
    function that is named without being called can only be the second kind, and is counted under
    ``<start> (as a value)``."""
    chosen: Counter[_Site] = Counter()
    inherits: Counter[_Site] = Counter()

    for rel, source in sources.items():
        tree = ast.parse(source)
        aliases = _aliases(tree)
        annotations = _annotation_nodes(tree)
        called: set[int] = set()

        def visit(
            node: ast.AST, classes: tuple[str, ...], function: str, built: frozenset[str]
        ) -> None:
            if isinstance(node, ast.ClassDef):
                classes = (*classes, node.name)
            elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                function = node.name  # the innermost function names the site
                built = _built_names(node, aliases)  # noqa: B023
            where = ".".join((*classes, function))
            if isinstance(node, ast.Call):
                called.add(id(node.func))  # noqa: B023
                start = _start_name(node.func, aliases)  # noqa: B023
                if start is not None:
                    name, takes_env = start
                    judged = takes_env and _chooses_an_environment(node, aliases, built)  # noqa: B023
                    (chosen if judged else inherits)[(rel, where, name)] += 1  # noqa: B023
            elif (
                isinstance(node, ast.Name | ast.Attribute)
                and isinstance(node.ctx, ast.Load)
                and id(node) not in called  # noqa: B023
                and id(node) not in annotations  # noqa: B023
            ):
                start = _start_name(node, aliases)  # noqa: B023
                if start is not None:
                    inherits[(rel, where, start[0] + _AS_A_VALUE)] += 1  # noqa: B023
            for child in ast.iter_child_nodes(node):
                visit(child, classes, function, built)

        visit(tree, (), "<module>", _built_names(tree, aliases))
    return chosen, inherits


@functools.cache
def _scanned_sources() -> Mapping[str, str]:
    """The engine and the toolkit, as the inventory keys them, plus the web console, which the
    engine mounts in its own process and the inventory does not read."""
    console = {f"{_CONSOLE.name}/{rel}": text for rel, text in _python_under(_CONSOLE).items()}
    return {**_package_sources(), **console}


@functools.cache
def _live_spawn_sites() -> tuple[Counter[_Site], Counter[_Site]]:
    """The shipped tree, parsed once for every test below. No test changes the result."""
    return _spawn_sites(_scanned_sources())


def test_every_process_the_engine_starts_is_given_an_environment() -> None:
    """One comparison, three failures it can report: a start nobody decided, a second start inside
    a listed function, and a listed site that has gone or now chooses its environment."""
    _chosen, inherits = _live_spawn_sites()
    listed = {site_key: _MORE_THAN_ONE.get(site_key, 1) for site_key in _INHERITS_ON_PURPOSE}
    assert dict(inherits) == listed, (
        "the starts that hand a child the caller's whole environment are not the ones listed in "
        "_INHERITS_ON_PURPOSE, in the numbers listed. Pass env= from a messagefoundry.childenv "
        "builder, or list the site with its reason."
    )


def test_the_guard_sees_the_calls_it_is_about() -> None:
    chosen, inherits = _live_spawn_sites()
    assert sorted(_MUST_CHOOSE - set(chosen)) == []
    assert sorted(_MUST_CHOOSE & set(inherits)) == []
    # Only these choose one today. Another is fine; it has to be a deliberate edit here.
    assert set(chosen) == _MUST_CHOOSE


def test_one_function_builds_the_command_line_of_a_python_child() -> None:
    """``python_child_argv`` is where the interpreter flags are added, so a Python child started any
    other way would start without them. Outside the tray, which is the desktop user's own process,
    it is the only code in the shipped packages that names this interpreter's executable."""
    names_the_interpreter = {
        rel
        for rel, source in _scanned_sources().items()
        if not rel.startswith("tray/")
        and any(
            isinstance(node, ast.Attribute)
            and node.attr == "executable"
            and isinstance(node.value, ast.Name)
            and node.value.id == "sys"
            for node in ast.walk(ast.parse(source))
        )
    }
    assert names_the_interpreter == {"childenv.py"}


def test_the_guard_reads_every_module_the_process_start_inventory_names() -> None:
    """Coverage, beside the finding: the inventory is a second reader of the same tree, and a module
    it says starts a process must be one this guard has a site in."""
    chosen, inherits = _live_spawn_sites()
    seen = {rel for rel, _function, _name in (*chosen, *inherits)}
    assert seen == set(_start_sites(_scanned_sources()))
    assert len(seen) >= 9
    assert any(rel.startswith(_CONSOLE.name + "/") for rel in _scanned_sources())


_FROM_A_BUILDER = "from messagefoundry.childenv import hook_environment\n"


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("import subprocess\ndef f():\n    subprocess.run(['x'])\n", False),
        ("import subprocess\ndef f():\n    subprocess.run(['x'], env=None)\n", False),
        ("import subprocess\ndef f():\n    subprocess.run(['x'], env={})\n", False),
        ("import os, subprocess\ndef f():\n    subprocess.run(['x'], env=os.environ)\n", False),
        (
            "import os, subprocess\ndef f():\n    subprocess.run(['x'], env=os.environ.copy())\n",
            False,
        ),
        (
            "import os, subprocess\ndef f():\n"
            "    subprocess.run(['x'], env={**os.environ, 'A': '1'})\n",
            False,
        ),
        ("import subprocess\ndef f(**kw):\n    subprocess.run(['x'], **kw)\n", False),
        ("import subprocess\ndef f(env):\n    subprocess.run(['x'], env=env)\n", False),
        ("import subprocess as sp\ndef f():\n    sp.Popen(['x'])\n", False),
        ("from subprocess import Popen\ndef f():\n    Popen(['x'])\n", False),
        ("import asyncio\nasync def f():\n    await asyncio.create_subprocess_shell('x')\n", False),
        (
            "from asyncio import create_subprocess_shell as css\nasync def f():\n    await css('x')\n",
            False,
        ),
        ("async def f(loop):\n    await loop.subprocess_exec(None, 'x')\n", False),
        (
            _FROM_A_BUILDER + "import subprocess\ndef f():\n"
            "    subprocess.run(['x'], env=hook_environment())\n",
            True,
        ),
        (
            "from messagefoundry import childenv\nfrom subprocess import check_output as co\n"
            "def f():\n    co(['x'], env=childenv.worker_environment())\n",
            True,
        ),
        (
            _FROM_A_BUILDER + "import asyncio\nasync def f():\n    env = hook_environment()\n"
            "    await asyncio.create_subprocess_exec('x', env=env)\n",
            True,
        ),
        (
            _FROM_A_BUILDER + "async def f(loop):\n"
            "    await loop.subprocess_exec(None, 'x', env=hook_environment())\n",
            True,
        ),
        # A start with no env= to pass can only ever be listed.
        ("import os\ndef f():\n    os.system('x')\n", False),
        (
            _FROM_A_BUILDER
            + "import os\ndef f():\n    os.startfile('x', env=hook_environment())\n",
            False,
        ),
        ("import os\ndef f():\n    os.execve('x', ['x'], {})\n", False),
    ],
)
def test_the_guard_reads_each_spelling_of_a_start(source: str, expected: bool) -> None:
    chosen, inherits = _spawn_sites({"m.py": source})
    assert (sum(chosen.values()), sum(inherits.values())) == ((1, 0) if expected else (0, 1))


def test_each_call_is_counted_and_a_method_is_keyed_by_its_class() -> None:
    source = (
        _FROM_A_BUILDER + "import subprocess\n"
        "class A:\n"
        "    def f(self):\n"
        "        subprocess.run(['x'], env=hook_environment())\n"
        "        subprocess.run(['y'])\n"
        "        subprocess.run(['z'])\n"
        "class B:\n"
        "    def f(self):\n"
        "        def inner():\n"
        "            subprocess.run(['w'])\n"
    )
    chosen, inherits = _spawn_sites({"m.py": source})
    assert dict(chosen) == {("m.py", "A.f", "subprocess.run"): 1}
    assert dict(inherits) == {
        ("m.py", "A.f", "subprocess.run"): 2,
        ("m.py", "B.inner", "subprocess.run"): 1,
    }


def test_a_start_passed_as_a_value_is_a_site_of_its_own() -> None:
    """A module that already has a listed call must not hide a second start that is handed to
    something else to call, and each such reference is counted."""
    source = (
        "import asyncio, subprocess\n"
        "async def f():\n"
        "    subprocess.run(['listed'])\n"
        "    await asyncio.to_thread(subprocess.run, ['unjudged'])\n"
        "    await asyncio.to_thread(subprocess.run, ['unjudged too'])\n"
    )
    _chosen, inherits = _spawn_sites({"m.py": source})
    assert dict(inherits) == {
        ("m.py", "f", "subprocess.run"): 1,
        ("m.py", "f", "subprocess.run" + _AS_A_VALUE): 2,
    }


@pytest.mark.parametrize(
    "body",
    [
        # Bound twice in the function.
        "def f():\n    env = hook_environment()\n    env = os.environ\n"
        "    subprocess.run(['x'], env=env)\n",
        # The parameter, while an inner function binds the same name from a builder.
        "def f(env):\n    def inner():\n        env = hook_environment()\n"
        "    subprocess.run(['x'], env=env)\n",
        # A module-level name, while a function binds the same name from a builder.
        "env = os.environ\ndef g():\n    env = hook_environment()\n"
        "def f():\n    subprocess.run(['x'], env=env)\n",
        # A class body does not inherit what a method binds.
        "class C:\n    def g(self):\n        env = hook_environment()\n"
        "    subprocess.run(['x'], env=env)\n",
    ],
)
def test_a_name_is_trusted_only_where_a_builder_bound_it_once(body: str) -> None:
    source = _FROM_A_BUILDER + "import os, subprocess\n" + body
    chosen, inherits = _spawn_sites({"m.py": source})
    assert (sum(chosen.values()), sum(inherits.values())) == (0, 1)


def test_a_call_that_starts_no_process_is_not_a_site() -> None:
    source = (
        "import os, subprocess\n"
        "def f(x, proc: subprocess.Popen):\n"
        "    held: subprocess.Popen | None = None\n"
        "    x.run()\n"
        "    os.path.join('a')\n"
        "    subprocess.list2cmdline(['a'])\n"
    )
    assert _spawn_sites({"m.py": source}) == (Counter(), Counter())
