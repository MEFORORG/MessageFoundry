# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Pin the cap on the worker count ``pytest -n auto`` starts (``tests/_xdist_worker_cap.py``).

One ``-n auto`` run takes at most ``MAX_AUTO_WORKERS`` workers, a smaller machine keeps its own
count, and ``PYTEST_XDIST_AUTO_NUM_WORKERS`` still sizes one run. The cap does nothing unless a
conftest pytest loads early registers it, so both registrations are pinned too.

The repo-root conftest is reached through this run's plugin manager, never imported: pytest
registers it under the bare name ``conftest``, which ``tests/test_conftest_name_collision_guard.py``
keeps unimported.
"""

from __future__ import annotations

import ast
from collections.abc import Callable
from pathlib import Path

import pytest

from tests import _xdist_worker_cap as cap

_ROOT = Path(__file__).resolve().parents[1]
_ROOT_CONFTEST = _ROOT / "conftest.py"
_CONSOLE_CONFTEST = _ROOT / "packaging" / "messagefoundry-webconsole" / "tests" / "conftest.py"


def test_the_cap_is_eight() -> None:
    assert cap.MAX_AUTO_WORKERS == 8


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


def test_the_root_conftest_registers_the_cap_in_this_run(pytestconfig: pytest.Config) -> None:
    """The premise: the root conftest is a loaded plugin and binds the shared hook."""
    for plugin in pytestconfig.pluginmanager.get_plugins():
        location = getattr(plugin, "__file__", None)
        if location and Path(location).resolve() == _ROOT_CONFTEST:
            hook = plugin.pytest_xdist_auto_num_workers
            assert hook is cap.pytest_xdist_auto_num_workers
            return
    pytest.fail(f"{_ROOT_CONFTEST} is not registered in this run, so -n auto is uncapped")


def test_the_console_conftest_registers_the_cap_too() -> None:
    """A run naming only the console tree never loads the root conftest; its own must bind the hook.

    Read by AST, not run: importing that conftest here would load the console suite's fixtures.
    """
    tree = ast.parse(_CONSOLE_CONFTEST.read_text(encoding="utf-8"))
    bound = {
        (node.module, alias.name, alias.asname)
        for node in tree.body
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
    }
    assert ("tests._xdist_worker_cap", "pytest_xdist_auto_num_workers", None) in bound


@pytest.fixture
def cpu_count(
    pytestconfig: pytest.Config, monkeypatch: pytest.MonkeyPatch
) -> Callable[[int], None]:
    """Set the CPU count xdist's own hook implementation reads, through psutil."""
    # Installed is not enough: under `-p no:xdist` the hook has no spec and returns a list.
    if not pytestconfig.pluginmanager.hasplugin("xdist"):
        pytest.skip("pytest-xdist is not active in this run, so no hook chain to drive")
    psutil = pytest.importorskip("psutil")
    monkeypatch.delenv(cap.AUTO_WORKERS_ENV, raising=False)

    def set_count(n: int) -> None:
        monkeypatch.setattr(psutil, "cpu_count", lambda logical=True: n)

    return set_count


@pytest.mark.parametrize(("cpus", "expected"), [(32, 8), (4, 4)])
def test_the_real_hook_chain_caps_xdists_count(
    pytestconfig: pytest.Config, cpu_count: Callable[[int], None], cpus: int, expected: int
) -> None:
    """Drive the registered hook chain: xdist's implementation computes, the wrapper bounds it."""
    cpu_count(cpus)
    assert pytestconfig.hook.pytest_xdist_auto_num_workers(config=pytestconfig) == expected


def test_the_env_override_still_wins_through_the_real_hook_chain(
    pytestconfig: pytest.Config, cpu_count: Callable[[int], None], monkeypatch: pytest.MonkeyPatch
) -> None:
    cpu_count(32)
    monkeypatch.setenv(cap.AUTO_WORKERS_ENV, "24")
    assert pytestconfig.hook.pytest_xdist_auto_num_workers(config=pytestconfig) == 24
