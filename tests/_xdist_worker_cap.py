# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cap the worker count ``pytest -n auto`` starts, for every testpath.

Two conftests register the hook below, because no single one is loaded for every invocation:

* the repo-root ``conftest.py``, which pytest loads for any run configured by the root
  ``pyproject.toml``, under either testpath;
* ``packaging/messagefoundry-webconsole/tests/conftest.py``, because a run that names only that
  tree takes the web console's own ``pyproject.toml`` as its config file and rootdir, and then never
  loads the repo-root conftest.

pytest-xdist resolves ``-n auto`` inside ``pytest_cmdline_main``, so only a conftest pytest loads
before that, an "initial conftest", can take part; that is why this cannot live in a fixture or in a
later hook. Where both conftests are loaded the wrapper runs twice, which is harmless: capping an
already capped count changes nothing, and an override passes through both.

Both import it package-qualified, the house idiom ``tests/test_conftest_name_collision_guard.py``
describes; the web console suite already reaches ``tests/_deadline_capture.py`` the same way.
"""

from __future__ import annotations

import os
from collections.abc import Generator

import pytest

#: The most workers ``-n auto`` (or ``-n logical``) may start in one run. Many sessions run pytest
#: at once on one development PC, and each ``-n auto`` run sizes itself to the whole machine, so
#: they fight for the same CPUs and memory. Measured 2026-11-18 on a 32-logical-CPU box: at least
#: seven concurrent pytest runs, 85 python processes and 27.8 GB of private memory. The cap is an
#: upper bound only: a machine with fewer CPUs, such as a 4 vCPU CI runner, keeps its own count.
MAX_AUTO_WORKERS = 8

#: pytest-xdist's own per-run override. Its hook implementation returns this value ahead of any CPU
#: count, and the wrapper below leaves that value uncapped, so it stays the way to size one run.
AUTO_WORKERS_ENV = "PYTEST_XDIST_AUTO_NUM_WORKERS"


def capped_auto_workers(computed: int, env_value: str | None) -> int:
    """Return the worker count for ``-n auto``, given what xdist computed and the override's value.

    A value xdist accepted from ``AUTO_WORKERS_ENV`` passes through unchanged, whatever its size.
    xdist ignores a non-integer value with a warning and falls back to its CPU count, so the cap
    still applies then.
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
