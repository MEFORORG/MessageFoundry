# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cap the worker count ``pytest -n auto`` starts, for every testpath.

pytest-xdist resolves ``-n auto`` inside ``pytest_cmdline_main``, so only a plugin pytest has
registered before that can take part: a ``-p`` plugin or an "initial conftest". That is why this
cannot live in a fixture or in a later hook. Three places register the hook below, because no one of
them reaches every invocation:

* the root ``pyproject.toml``, whose ``addopts`` carries ``-p tests._xdist_worker_cap``, for every
  run that file configures. That includes the runs no conftest reaches in time: ``pytest -n auto
  packaging`` from the repository root and ``pytest -n auto`` from ``packaging/`` (each collects the
  console suite, whose conftest loads only during collection, after xdist has sized the run), and
  ``--noconftest``. Each of the three resolved to 16 workers on a 16-core box before this line was
  added, and to 8 after it;
* ``tests/conftest.py``, for runs whose arguments reach it before collection: no arguments (pytest
  uses ``testpaths``), a ``tests/...`` argument, or ``.``, because pytest also loads the conftest of
  each ``test*`` directory DIRECTLY under an argument;
* ``packaging/messagefoundry-webconsole/tests/conftest.py``, because a run that names only that
  tree takes the web console's own ``pyproject.toml`` as its config file and rootdir, so neither the
  root ``addopts`` nor ``tests/conftest.py`` applies to it.

The ``-p`` import needs ``tests`` importable before any conftest runs, which the editable install
gives: it puts the checkout root on ``sys.path`` from any working directory, and every CI install
that runs pytest, like ``scripts/worktree/ensure-venv.ps1``, is editable. ``tests/conftest.py``
already imports ``tests`` the same way, so this adds no new requirement, only an earlier failure.

Where more than one registration is loaded the wrapper runs once for each, which is harmless:
capping an already capped count changes nothing, and an override passes through every one. pluggy
accepts the shared function because each registration is a different plugin object.

No repo-root ``conftest.py`` registers it: importing one under pytest's default ``prepend`` mode
moves the repository root to the front of ``sys.path``, which silences the cross-checkout refusal
in ``tests/conftest.py`` and changes where ``messagefoundry_webconsole`` is imported from.

The conftests import it package-qualified, the house idiom
``tests/test_conftest_name_collision_guard.py`` describes; the web console suite already reaches
``tests/_deadline_capture.py`` the same way.

At least these runs stay uncapped: a ``-c`` naming a config other than the two above, an
``addopts`` override (``-o addopts=...``) on a run no conftest reaches in time, and ``-p
no:tests._xdist_worker_cap`` on such a run. The cap is per run, not per machine: seven concurrent
runs can still start seven times ``MAX_AUTO_WORKERS``.

WHY NOT xdist's ``--maxprocesses`` IN ``addopts``. It would cap without code, but it also caps an
explicit ``-n N``, which this cap deliberately leaves alone, and a run under ``-p no:xdist`` (the web
console suite's file-balance test spawns one) would refuse the unknown option.
"""

from __future__ import annotations

import os
from collections.abc import Generator

import pytest

#: The most workers ``-n auto`` (or ``-n logical``) starts in one run when ``AUTO_WORKERS_ENV`` is
#: unset or not an integer; a valid override is not capped. Many sessions run pytest at once on one
#: development PC, and each ``-n auto`` run sizes itself to the machine's physical cores (16 on that
#: box), so they fight for the same CPUs and memory. Measured 2026-11-18 on a 32-logical-CPU box: at
#: least seven concurrent pytest runs, 85 python processes and 27.8 GB of private memory. The cap is
#: an upper bound only: a machine with fewer cores, such as a 4 vCPU CI runner, keeps its own count.
MAX_AUTO_WORKERS = 8

#: pytest-xdist's own per-run override. Its hook implementation returns this value ahead of any CPU
#: count, and the wrapper below leaves that value uncapped, so it stays the way to size one run.
AUTO_WORKERS_ENV = "PYTEST_XDIST_AUTO_NUM_WORKERS"


def capped_auto_workers(computed: int, env_value: str | None) -> int:
    """Return the worker count for ``-n auto``, given what xdist computed and the override's value.

    A value xdist accepted from ``AUTO_WORKERS_ENV`` passes through unchanged, whatever its size.
    xdist ignores a non-integer value with a warning and falls back to its CPU count, so the cap
    still applies then. This mirrors xdist 3.8.0's own parse (``if env_var: int(env_var)``), read
    from its ``plugin.py``; it infers from the variable, not from which implementation answered.
    """
    try:
        int(env_value or "")
    except ValueError:
        return min(MAX_AUTO_WORKERS, computed)
    return computed


# A wrapper, so xdist still computes the count (its env override, then psutil's physical cores, or
# logical ones for `-n logical`, then os fallbacks) and this only bounds the result. xdist calls this
# hook for both `auto` and `logical`; an explicit `-n N` never reaches it. `optionalhook` keeps a run
# without xdist active from failing on an unknown hook name; nothing calls the hook in such a run.
@pytest.hookimpl(wrapper=True, optionalhook=True)
def pytest_xdist_auto_num_workers(config: pytest.Config) -> Generator[None, int, int]:
    computed = yield
    return capped_auto_workers(computed, os.environ.get(AUTO_WORKERS_ENV))
