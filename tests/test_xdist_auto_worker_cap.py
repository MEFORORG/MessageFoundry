# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Pin the cap on the worker count ``pytest -n auto`` starts, and both conftests that register it.

The module under test, ``tests/_xdist_worker_cap.py``, says why there are two registrations.
"""

from __future__ import annotations

import ast
from collections.abc import Callable
from pathlib import Path

import pytest

from tests import _xdist_worker_cap as cap

_ROOT = Path(__file__).resolve().parents[1]
_TESTS_CONFTEST = _ROOT / "tests" / "conftest.py"
_CONSOLE_CONFTEST = _ROOT / "packaging" / "messagefoundry-webconsole" / "tests" / "conftest.py"


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
    pytest.fail(f"{_TESTS_CONFTEST} is not registered in this run, so -n auto is uncapped")


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
