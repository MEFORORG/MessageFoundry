# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cap the worker count ``pytest -n auto`` starts, for every testpath.

pytest-xdist resolves ``-n auto`` inside ``pytest_cmdline_main``, so only a plugin pytest has
registered before that can take part, at least a ``-p`` plugin, an installed entry point, or an
"initial conftest". That is why this cannot live in a fixture or in a later hook.

The PRIMARY registration is ``-p tests._xdist_worker_cap`` in the ``addopts`` of both pytest
configs, the root ``pyproject.toml`` and ``packaging/messagefoundry-webconsole/pyproject.toml``
(a run that names only the console tree takes that file as its config and rootdir). It reaches the
runs either file configures that keep its ``addopts``, including at least these runs no conftest
reaches in time: ``pytest -n auto packaging`` from the repository root and ``pytest -n auto`` from
``packaging/`` (each collects the console suite, whose conftest loads only during collection, after
xdist has sized the run), and ``--noconftest`` under either config. Measured with the real core
count on a 16-core box, the three root-configured ones resolved to 16 workers before the ``-p``
entries were added; each run named here resolved to 8 after.

The two conftests, ``tests/conftest.py`` and the console suite's, still import the hook as well,
so a run that overrides ``addopts`` (``-o addopts=...``) and loads one of them in time stays capped.
Where more than one registration is loaded the wrapper runs once for each, which is harmless:
capping an already capped count changes nothing, and an override passes through every one. pluggy
accepts the shared function because each registration is a different plugin object.

THE ``-p`` ENTRIES NEED ``tests`` IMPORTABLE AT STARTUP, before any conftest, from whatever working
directory pytest runs in. The editable install gives that: it puts the checkout root on ``sys.path``.
The CI jobs that ran pytest when this was written installed editable, and so does
``scripts/worktree/ensure-venv.ps1``; a job that installs otherwise fails at startup. For a
run that loads either conftest this is no new requirement, since both import ``tests`` already. A
run under either config that loads neither, at least a root-configured one and a console-configured
``--noconftest`` run, did not need it before, and under an install that does not put the checkout
root on ``sys.path`` it now fails at startup.

No repo-root ``conftest.py`` registers it: importing one under pytest's default ``prepend`` mode
moves the repository root to the front of ``sys.path``, which silences the cross-checkout refusal
in ``tests/conftest.py`` and changes where ``messagefoundry_webconsole`` is imported from.

The conftests import it package-qualified, the house idiom
``tests/test_conftest_name_collision_guard.py`` describes; the web console suite already reaches
``tests/_deadline_capture.py`` the same way.

At least these runs stay uncapped: a ``-c`` naming a config other than the two above, and an
``addopts`` override or ``-p no:tests._xdist_worker_cap`` on a run no conftest reaches in time
(``-o addopts=--timeout=60`` with ``packaging`` from the root measured 16). The cap is per run, not
per machine: seven concurrent runs can still start seven times ``MAX_AUTO_WORKERS``.

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
