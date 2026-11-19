# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Pin the cap on the worker count ``pytest -n auto`` starts, and the three places that register it.

The module under test, ``tests/_xdist_worker_cap.py``, says why there are three registrations: the
root ``addopts`` and two conftests.
"""

from __future__ import annotations

import ast
import os
import re
import shlex
import subprocess
import sys
import tomllib
from collections.abc import Callable
from pathlib import Path

import pytest

from tests import _xdist_worker_cap as cap

_ROOT = Path(__file__).resolve().parents[1]
_TESTS_CONFTEST = _ROOT / "tests" / "conftest.py"
_CONSOLE_CONFTEST = _ROOT / "packaging" / "messagefoundry-webconsole" / "tests" / "conftest.py"
_PLUGIN_ARG = "tests._xdist_worker_cap"


@pytest.mark.parametrize(
    ("computed", "expected"), [(32, 8), (16, 8), (9, 8), (8, 8), (4, 4), (1, 1)]
)
def test_a_computed_count_is_capped_only_from_above(computed: int, expected: int) -> None:
    assert cap.capped_auto_workers(computed, None) == expected
    assert cap.capped_auto_workers(computed, "") == expected


def test_a_valid_override_passes_through_uncapped() -> None:
    assert cap.capped_auto_workers(24, "24") == 24
    assert cap.capped_auto_workers(0, "0") == 0


def test_an_override_xdist_ignored_does_not_lift_the_cap() -> None:
    # xdist warns on a non-integer value and falls back to its CPU count; that count is still capped.
    assert cap.capped_auto_workers(16, "many") == 8


def test_the_tests_conftest_registers_the_cap_in_this_run(pytestconfig: pytest.Config) -> None:
    """The premise: ``tests/conftest.py`` is a loaded plugin and binds the shared hook.

    Reached through the plugin manager, never imported, because pytest registers it under the bare
    name ``conftest``. Unlike the hook-chain test below, this holds even where xdist is inactive.
    """
    for plugin in pytestconfig.pluginmanager.get_plugins():
        location = getattr(plugin, "__file__", None)
        if location and Path(location).resolve() == _TESTS_CONFTEST:
            hook = plugin.pytest_xdist_auto_num_workers
            assert hook is cap.pytest_xdist_auto_num_workers
            return
    pytest.fail(
        f"{_TESTS_CONFTEST} is not registered in this run, so a run that overrides addopts is "
        "uncapped; tests/_xdist_worker_cap.py says what each registration covers"
    )


def _binds_the_cap(source: str) -> bool:
    """Whether ``source`` imports the cap hook, under its own name, as a bare module-level statement.

    Bare, not guarded: the console suite already needs ``tests/`` importable, so a guard would only
    let a fault drop the cap silently.
    """
    name = "pytest_xdist_auto_num_workers"
    bound = False
    for node in ast.parse(source).body:
        if isinstance(node, ast.ImportFrom) and any(
            a.asname is None and a.name == name for a in node.names
        ):
            bound = node.module == "tests._xdist_worker_cap"
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            bound = False
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Delete)):
            # pluggy registers what the name holds last, so a later rebinding drops the cap.
            targets = node.targets if isinstance(node, (ast.Assign, ast.Delete)) else [node.target]
            if any(isinstance(t, ast.Name) and t.id == name for t in targets):
                bound = False
    return bound


def test_the_console_conftest_registers_the_cap_too() -> None:
    """A run naming only the console tree never loads tests/conftest.py; its own must bind the hook.

    Read by AST, not run: importing that conftest here would load the console suite's fixtures. It
    proves the import is written, not that a console-rooted run resolves it; the smoke run recorded
    in the PR measured that.
    """
    assert _binds_the_cap(_CONSOLE_CONFTEST.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "source",
    [
        "import os\n",
        "try:\n    from tests._xdist_worker_cap import pytest_xdist_auto_num_workers\n"
        "except ImportError:\n    pass\n",
        "def f():\n    from tests._xdist_worker_cap import pytest_xdist_auto_num_workers\n",
        "from tests._xdist_worker_cap import pytest_xdist_auto_num_workers as other\n",
        "try:\n    from tests._xdist_worker_cap import pytest_xdist_auto_num_workers\n"
        "except ModuleNotFoundError:\n    pass\n",
        "try:\n    from tests._xdist_worker_cap import pytest_xdist_auto_num_workers\n"
        "except ModuleNotFoundError:\n    raise\nexcept ImportError:\n    pass\n",
        "from tests._xdist_worker_cap import pytest_xdist_auto_num_workers\n"
        "pytest_xdist_auto_num_workers = None\n",
        "from tests._xdist_worker_cap import pytest_xdist_auto_num_workers\n"
        "del pytest_xdist_auto_num_workers\n",
        "from tests._xdist_worker_cap import pytest_xdist_auto_num_workers\n"
        "def pytest_xdist_auto_num_workers(config):\n    return 64\n",
    ],
    ids=[
        "absent",
        "swallows-every-import-error",
        "not-module-level",
        "renamed",
        "swallows-a-missing-module",
        "two-handlers",
        "rebound",
        "deleted",
        "redefined",
    ],
)
def test_the_console_binding_check_goes_red_without_the_binding(source: str) -> None:
    """Negative control: the check above must be able to fail."""
    assert not _binds_the_cap(source)


@pytest.fixture
def hook_with_cpus(
    pytestconfig: pytest.Config, monkeypatch: pytest.MonkeyPatch
) -> Callable[[int], int]:
    """Call the registered hook chain with psutil reporting ``n`` CPUs for that call only.

    Patched only around the call, which shortens, but does not close, the window in which
    another thread in this worker could read the fake count.
    """
    # Installed is not enough: under `-p no:xdist` the hook has no spec and returns a list.
    if not pytestconfig.pluginmanager.hasplugin("xdist"):
        pytest.skip("pytest-xdist is not active in this run, so no hook chain to drive")
    psutil = pytest.importorskip("psutil")

    def call(n: int) -> int:
        with monkeypatch.context() as patch:
            patch.setattr(psutil, "cpu_count", lambda logical=True: n)
            result: int = pytestconfig.hook.pytest_xdist_auto_num_workers(config=pytestconfig)
        return result

    return call


@pytest.mark.parametrize(
    ("cpus", "override", "expected"), [(32, None, 8), (4, None, 4), (32, "24", 24)]
)
def test_the_real_hook_chain_caps_xdists_count(
    hook_with_cpus: Callable[[int], int],
    monkeypatch: pytest.MonkeyPatch,
    cpus: int,
    override: str | None,
    expected: int,
) -> None:
    """Drive the registered hook chain: xdist's implementation computes, the wrapper bounds it."""
    if override is None:
        monkeypatch.delenv(cap.AUTO_WORKERS_ENV, raising=False)
    else:
        monkeypatch.setenv(cap.AUTO_WORKERS_ENV, override)
    assert hook_with_cpus(cpus) == expected


def _loads_the_cap(addopts: str | list[str]) -> bool:
    """Whether ``addopts`` loads ``tests._xdist_worker_cap`` with ``-p`` and does not block it.

    Takes the string form or the list form. Both ``-p NAME`` and ``-pNAME`` count.
    """
    words = shlex.split(addopts) if isinstance(addopts, str) else list(addopts)
    names = [
        nxt if word == "-p" else word[2:]
        for word, nxt in zip(words, [*words[1:], ""], strict=True)
        if word == "-p" or (word.startswith("-p") and len(word) > 2)
    ]
    return _PLUGIN_ARG in names and f"no:{_PLUGIN_ARG}" not in names


@pytest.mark.parametrize(
    "config",
    [
        _ROOT / "pyproject.toml",
        _ROOT / "packaging" / "messagefoundry-webconsole" / "pyproject.toml",
    ],
    ids=["root", "console"],
)
def test_each_pytest_config_loads_the_cap_as_a_plugin(config: Path) -> None:
    """The registration that reaches the runs no conftest is loaded in time for."""
    cfg = tomllib.loads(config.read_text(encoding="utf-8"))
    addopts = cfg["tool"]["pytest"]["ini_options"]["addopts"]
    assert _loads_the_cap(addopts), f"{config} addopts no longer loads {_PLUGIN_ARG}: {addopts!r}"


@pytest.mark.parametrize(
    "addopts",
    [
        "--timeout=60",
        "-p no:tests._xdist_worker_cap",
        "-p tests._xdist_worker",
        "tests._xdist_worker_cap",
        "-p tests._xdist_worker_cap -p no:tests._xdist_worker_cap",
        ["--timeout=60", "-p"],
    ],
    ids=["absent", "blocked", "other-module", "no-flag", "loaded-then-blocked", "list-dangling-p"],
)
def test_the_addopts_check_goes_red_without_the_plugin(addopts: str | list[str]) -> None:
    """Negative control: the check above must be able to fail."""
    assert not _loads_the_cap(addopts)


@pytest.mark.parametrize(
    "addopts",
    ["-p tests._xdist_worker_cap", "-ptests._xdist_worker_cap", ["-p", "tests._xdist_worker_cap"]],
    ids=["spaced", "joined", "list"],
)
def test_the_addopts_check_accepts_each_spelling(addopts: str | list[str]) -> None:
    """Positive control: a spelling pytest accepts must pass, so a green above is not vacuous."""
    assert _loads_the_cap(addopts)


#: What the child's xdist reports as the machine's count: more than the cap, so a capped run differs.
_FAKE_CPUS = 32

# Loaded into the child with `-p`. It answers xdist's own hook ahead of xdist (tryfirst), so the count
# the cap's wrapper sees is this fixed number rather than the host's cores. It then prints what xdist
# resolved `-n auto` to, and the file the cap module came from, and ends the run inside
# pytest_cmdline_main, before any worker is started.
_PROBE = f"""\
import sys

import pytest


@pytest.hookimpl(tryfirst=True, optionalhook=True)
def pytest_xdist_auto_num_workers(config):
    return {_FAKE_CPUS}


def pytest_cmdline_main(config):
    module = sys.modules.get("{_PLUGIN_ARG}")
    print(f"CAP_MODULE={{getattr(module, '__file__', None)}}", flush=True)
    print(f"RESOLVED_WORKERS={{config.option.numprocesses}}", flush=True)
    return 0
"""


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        # Root-configured, and it collects only the console suite, whose conftest loads after xdist
        # has sized the run. Uncapped (32) before the root addopts loaded the cap. The module's
        # docstring records the other rows measured by hand, `--noconftest` among them; each child
        # costs a pytest startup, so only this one and its control run here.
        (["packaging"], cap.MAX_AUTO_WORKERS),
        # Control: block the plugin and the same run is uncapped, so the probe's count reaches xdist
        # and the cap in the row above comes from the addopts plugin, not from something else.
        (["-p", f"no:{_PLUGIN_ARG}", "packaging"], _FAKE_CPUS),
    ],
    ids=["packaging-from-root", "control-plugin-blocked"],
)
def test_a_root_configured_run_resolves_auto_to_the_cap(
    tmp_path: Path, args: list[str], expected: int
) -> None:
    """Run a child pytest from the repository root and read the count xdist resolved ``-n auto`` to.

    ``-P`` keeps the working directory off the child's ``sys.path``, as the ``pytest`` console script
    does, so ``tests`` must import the way a real run imports it: through the editable install. That
    install may name another checkout, so the child also reports where the cap module came from.
    """
    pytest.importorskip("xdist", reason="the child needs pytest-xdist to resolve -n auto")
    assert _FAKE_CPUS > cap.MAX_AUTO_WORKERS
    (tmp_path / "_mf_worker_count_probe.py").write_text(_PROBE, encoding="utf-8")
    env = {
        k: v
        for k, v in os.environ.items()
        if k
        not in {
            "PYTEST_ADDOPTS",
            "PYTEST_PLUGINS",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD",
            cap.AUTO_WORKERS_ENV,
        }
    }
    env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(tmp_path), env.get("PYTHONPATH")]))
    argv = [sys.executable, "-P", "-m", "pytest", "-p", "_mf_worker_count_probe"]
    argv += ["-p", "no:cacheprovider", "-n", "auto", *args]
    proc = subprocess.run(
        argv,
        cwd=_ROOT,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=45,
        check=False,
    )
    found = re.findall(r"^RESOLVED_WORKERS=(\S+)$", proc.stdout, re.MULTILINE)
    assert proc.returncode == 0 and found, (
        f"the child did not report a count (exit {proc.returncode}):\n"
        f"{proc.stdout[-2000:]}\n{proc.stderr[-2000:]}"
    )
    sources = re.findall(r"^CAP_MODULE=(.+)$", proc.stdout, re.MULTILINE)
    assert sources and sources[0] != "None", f"the child never imported {_PLUGIN_ARG}"
    assert Path(sources[0]).resolve() == Path(cap.__file__).resolve(), (
        f"the child imported {_PLUGIN_ARG} from {sources[0]}, not this checkout's "
        f"{cap.__file__}: the editable install names another checkout"
    )
    assert found == [str(expected)], f"{shlex.join(argv[3:])} resolved -n auto to {found}"
