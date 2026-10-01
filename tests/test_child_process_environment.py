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
import re
import site
import subprocess
import sys
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

import messagefoundry
from messagefoundry import childenv
from messagefoundry.config import settings
from messagefoundry.config.environments import VALUE_ENV_PREFIX
from messagefoundry.config.run_context import RunContext
from messagefoundry.config.wiring import Registry, load_config
from messagefoundry.pipeline import dr, supervisor
from messagefoundry.pipeline.dryrun import transform_one
from tests.test_dangerous_functionality_doc import (
    _ATTRIBUTE_STARTS,
    _OS_EXEC_RE,
    _START_FORMS,
    _SUBPROCESS_FUNCS,
    _aliases,
    _dotted,
    _package_sources,
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

#: Every environment name the engine calls a secret: the registry's fixed names, one ``env()``
#: connection secret (the prefix is fixed, the suffix is the operator's), and the one name outside
#: the engine's namespace that it may still rely on.
_SECRET_NAMES = frozenset(
    {name for name in CRITICAL_SECRETS if name.startswith(childenv.ENGINE_ENV_PREFIX)}
    | {VALUE_ENV_PREFIX + "PARTNER_PASSWORD", "VAULT_TOKEN"}
)

_PACKAGE_ROOT = str(Path(messagefoundry.__file__).resolve().parent.parent)


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
    return Send(
        "OB_ENV",
        "SAFE=" + str(sys.flags.safe_path) + ";MARKER=" + marker + ";MF=" + messagefoundry.__file__,
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
    assert captured["argv"][1:3] == [childenv.SAFE_PATH_FLAG, "-m"]


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


def test_a_named_engine_switch_crosses_and_nothing_else_in_the_namespace_does() -> None:
    switch = settings.INSECURE_CONFIG_SOURCE_ESCAPE_ENV
    env = childenv.worker_environment(_parent_environment(), engine_switches=(switch,))
    assert {n for n in env if n.startswith(childenv.ENGINE_ENV_PREFIX)} == {switch}


def test_the_hook_environment_drops_the_engine_namespace_and_nothing_else() -> None:
    parent = _parent_environment()
    env = childenv.hook_environment(parent)
    dropped = set(parent) - set(env)
    assert dropped == {
        n for n in parent if n.startswith(childenv.ENGINE_ENV_PREFIX) or n == "VAULT_TOKEN"
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


def test_the_python_children_are_told_where_the_parents_package_is(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``-P`` takes the working directory off the child's import path. An engine run from a source
    checkout found its own package there, so the child is told the location instead."""
    monkeypatch.setattr(site, "getsitepackages", lambda: [])
    monkeypatch.setattr(site, "getusersitepackages", lambda: "")
    for build in (childenv.worker_environment, childenv.engine_environment):
        env = build({"PYTHONPATH": "operator-path"})
        assert env["PYTHONPATH"].split(os.pathsep) == [_PACKAGE_ROOT, "operator-path"]
        assert build({})["PYTHONPATH"] == _PACKAGE_ROOT
        # A child of a child: the location is already first, so it is not stacked again.
        assert build(env)["PYTHONPATH"] == env["PYTHONPATH"]


def test_an_installed_package_adds_nothing_to_the_childs_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Installed in site-packages, the child finds the package by itself. Naming site-packages on
    ``PYTHONPATH`` would move it ahead of the standard library."""
    monkeypatch.setattr(site, "getsitepackages", lambda: [_PACKAGE_ROOT])
    for build in (childenv.worker_environment, childenv.engine_environment):
        assert "PYTHONPATH" not in build({})
        assert build({"PYTHONPATH": "operator-path"})["PYTHONPATH"] == "operator-path"


# --- the static guard ---------------------------------------------------------------------------
#
# The names that start a process, the alias resolution and the scanned tree are the process-start
# inventory's own (tests/test_dangerous_functionality_doc.py), imported so the two cannot disagree
# about which names start a process or which files are read. That inventory asks which MODULES start
# a process and in what form. This guard asks a different question, call by call: does each one name
# the child's environment. The walk over calls is this file's own.

#: Starts that accept ``env=``: the ``subprocess`` functions, and the asyncio spellings whether
#: written on the module or on an event loop. Every other start has no ``env=`` to pass.
_ASYNCIO_START_RE = re.compile(r"^(?:create_)?subprocess_(?:shell|exec)$")

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

#: Calls that hand the child the caller's environment on purpose, as ``(module, enclosing function,
#: start)``, each with its reason. None of them runs code an operator or a config author supplied.
#: An entry covers ONE call: a second start added to a listed function fails the guard.
_INHERITS_ON_PURPOSE: dict[tuple[str, str, str], str] = {
    ("auth/trust_anchors.py", "dacl_is_owner_only", "subprocess.run"): _PINNED_TOOL,
    ("store/store.py", "_secure_file", "subprocess.run"): _PINNED_TOOL,
    ("store/store.py", "_grant_read", "subprocess.run"): _PINNED_TOOL,
    ("service.py", "service_state", "subprocess.run"): _PINNED_TOOL,
    ("service.py", "control_service", "ShellExecuteW"): _SERVICE_CONTROL,
    ("service.py", "_runas_wait", "ShellExecuteExW"): _SERVICE_CONTROL,
    ("service.py", "install_service", "ShellExecuteW"): _SERVICE_CONTROL,
    ("service_status.py", "_query", "subprocess.run"): _PINNED_TOOL,
    ("tray/actions.py", "_run_detached", "subprocess.Popen"): _TRAY_OPENS_FOR_ITS_USER,
    ("tray/actions.py", "_open_path", "os.startfile"): _TRAY_OPENS_FOR_ITS_USER,
    ("tray/actions.py", "_open_path", "webbrowser.open"): _TRAY_OPENS_FOR_ITS_USER,
    ("tray/app.py", "TrayApp._edit_settings", "os.startfile"): _TRAY_OPENS_FOR_ITS_USER,
    ("tray/branding.py", "relaunch_branded", "subprocess.Popen"): (
        "the tray starting itself again under its branded launcher: the same program, as the same "
        "desktop user, so it needs the environment it already has"
    ),
}

#: The sites this change is about. They are also the positive control: a walker that could not see
#: a call would report a clean tree, so these three must be seen, and seen passing ``env=``.
_MUST_PASS_ENV = frozenset(
    {
        ("pipeline/sandbox.py", "SandboxSession._spawn", "subprocess.Popen"),
        ("pipeline/dr.py", "_run_command", "create_subprocess_shell"),
        ("pipeline/supervisor.py", "_default_spawn", "create_subprocess_exec"),
    }
)

_Site = tuple[str, str, str]


def _start(call: ast.Call, aliases: Mapping[str, str]) -> tuple[str, bool] | None:
    """``(the start a call makes, whether that start accepts env=)``, or ``None`` for any other call."""
    func = call.func
    dotted = _dotted(func, aliases)
    if dotted in _SUBPROCESS_FUNCS:
        return dotted, True
    last = func.attr if isinstance(func, ast.Attribute) else (dotted or "").rpartition(".")[2]
    if last and any(pattern.match(last) for pattern, _form in _ATTRIBUTE_STARTS):
        return last, _ASYNCIO_START_RE.match(last) is not None
    if dotted is not None and (dotted in _START_FORMS or _OS_EXEC_RE.match(dotted)):
        return dotted, False
    return None


def _names_an_environment(call: ast.Call) -> bool:
    """Whether the call passes ``env=``. ``env=None`` means inherit, so it does not count; neither
    does ``**kwargs``, which may or may not carry one."""
    for keyword in call.keywords:
        if keyword.arg == "env":
            return not (isinstance(keyword.value, ast.Constant) and keyword.value.value is None)
    return False


def _spawn_sites(sources: Mapping[str, str]) -> tuple[Counter[_Site], Counter[_Site]]:
    """Every process-starting call in ``sources``, counted per site: ``(calls that name the child's
    environment, calls that do not)``. A site is ``(module, enclosing function, start)``, and the
    function is qualified by its classes, so two methods of one name stay apart."""
    named: Counter[_Site] = Counter()
    inherits: Counter[_Site] = Counter()

    def visit(
        node: ast.AST, rel: str, aliases: Mapping[str, str], classes: tuple[str, ...], function: str
    ) -> None:
        if isinstance(node, ast.ClassDef):
            classes = (*classes, node.name)
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            function = node.name  # the innermost function names the site
        if isinstance(node, ast.Call):
            start = _start(node, aliases)
            if start is not None:
                name, takes_env = start
                site_key = (rel, ".".join((*classes, function)), name)
                (named if takes_env and _names_an_environment(node) else inherits)[site_key] += 1
        for child in ast.iter_child_nodes(node):
            visit(child, rel, aliases, classes, function)

    for rel, source in sources.items():
        tree = ast.parse(source)
        visit(tree, rel, _aliases(tree), (), "<module>")
    return named, inherits


@functools.cache
def _live_spawn_sites() -> tuple[Counter[_Site], Counter[_Site]]:
    """The shipped tree, parsed once for every test below. No test changes the result."""
    return _spawn_sites(_package_sources())


def test_every_process_the_engine_starts_is_given_an_environment() -> None:
    """One comparison, three failures it can report: a start nobody decided, a second start inside
    a listed function, and a listed site that has gone or now names its environment."""
    _named, inherits = _live_spawn_sites()
    assert dict(inherits) == dict.fromkeys(_INHERITS_ON_PURPOSE, 1), (
        "the calls that start a process with the caller's whole environment are not the ones listed "
        "in _INHERITS_ON_PURPOSE, one call each. Pass env= from messagefoundry.childenv, or list the "
        "site with its reason."
    )


def test_the_guard_sees_the_calls_it_is_about() -> None:
    named, inherits = _live_spawn_sites()
    assert sorted(_MUST_PASS_ENV - set(named)) == []
    assert sorted(_MUST_PASS_ENV & set(inherits)) == []


def test_the_guard_reads_every_module_the_process_start_inventory_names() -> None:
    """Coverage, beside the finding. The inventory finds a start wherever its name is read; this
    guard reads calls. A module the inventory names and this guard has no site in would hold a
    start the guard cannot judge, such as a start function passed as a value and called elsewhere."""
    named, inherits = _live_spawn_sites()
    seen = {rel for rel, _function, _name in (*named, *inherits)}
    assert seen == set(_start_sites(_package_sources()))
    assert len(seen) >= 9


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("import subprocess\ndef f():\n    subprocess.run(['x'])\n", False),
        ("import subprocess\ndef f():\n    subprocess.run(['x'], env={})\n", True),
        ("import subprocess\ndef f():\n    subprocess.run(['x'], env=None)\n", False),
        ("import subprocess\ndef f(**kw):\n    subprocess.run(['x'], **kw)\n", False),
        ("import subprocess as sp\ndef f():\n    sp.Popen(['x'])\n", False),
        ("from subprocess import Popen\ndef f():\n    Popen(['x'])\n", False),
        ("from subprocess import check_output as co\ndef f():\n    co(['x'], env={})\n", True),
        ("import asyncio\nasync def f():\n    await asyncio.create_subprocess_shell('x')\n", False),
        (
            "import asyncio\nasync def f():\n    await asyncio.create_subprocess_exec('x', env={})\n",
            True,
        ),
        (
            "from asyncio import create_subprocess_shell as css\nasync def f():\n    await css('x')\n",
            False,
        ),
        ("async def f(loop):\n    await loop.subprocess_exec(None, 'x')\n", False),
        ("async def f(loop):\n    await loop.subprocess_exec(None, 'x', env={})\n", True),
        # A start with no env= to pass can only ever be listed.
        ("import os\ndef f():\n    os.system('x')\n", False),
        ("import os\ndef f():\n    os.startfile('x', env={})\n", False),
        ("import os\ndef f():\n    os.execve('x', ['x'], {})\n", False),
    ],
)
def test_the_guard_reads_each_spelling_of_a_start(source: str, expected: bool) -> None:
    named, inherits = _spawn_sites({"m.py": source})
    assert (sum(named.values()), sum(inherits.values())) == ((1, 0) if expected else (0, 1))


def test_each_call_is_counted_and_a_method_is_keyed_by_its_class() -> None:
    source = (
        "import subprocess\n"
        "class A:\n"
        "    def f(self):\n"
        "        subprocess.run(['x'], env={})\n"
        "        subprocess.run(['y'])\n"
        "        subprocess.run(['z'])\n"
        "class B:\n"
        "    def f(self):\n"
        "        def inner():\n"
        "            subprocess.run(['w'])\n"
    )
    named, inherits = _spawn_sites({"m.py": source})
    assert dict(named) == {("m.py", "A.f", "subprocess.run"): 1}
    assert dict(inherits) == {
        ("m.py", "A.f", "subprocess.run"): 2,
        ("m.py", "B.inner", "subprocess.run"): 1,
    }


def test_a_call_that_starts_no_process_is_not_a_site() -> None:
    source = (
        "import os, subprocess\n"
        "def f(x, proc: subprocess.Popen):\n"
        "    x.run()\n"
        "    os.path.join('a')\n"
        "    subprocess.list2cmdline(['a'])\n"
    )
    assert _spawn_sites({"m.py": source}) == (Counter(), Counter())
