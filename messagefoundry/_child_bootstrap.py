# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Start one ``messagefoundry`` module in a child process, from the build this file belongs to.

Run as a script, never imported by the engine: ``python <flags> <this file> <module> [args...]``,
which is what :func:`messagefoundry.childenv.python_child_argv` builds (vault BACKLOG #2587). The
flags include ``-P``, which keeps the working directory off the child's import path. An engine run
from a source checkout that is not installed found its own package exactly there, so the child has
to be told where the package is. This file knows: it sits inside it. It does two things, then runs
the module the way ``python -m`` would.

* **It loads this build's ``messagefoundry`` package by its location, before anything can import
  it by name.** Every later ``import messagefoundry...`` in the child then resolves inside this
  build, wherever another copy sits on the path. Path order alone cannot promise that: an inherited
  ``PYTHONPATH`` entry is searched ahead of anything this file could add.
* **It puts the package's parent directory on ``sys.path``, after the standard library and ahead
  of the site-packages directories that follow it**, unless it is on the path already, which is
  the installed case. That is for the packages that ship beside this one in a checkout. After the
  standard library, so nothing in that directory can stand in for a standard-library module. That
  holds when an inherited ``PYTHONPATH`` names a site-packages directory, which then sits ahead of
  the standard library: the search for a site-packages directory starts after the standard
  library's last entry. A standard-library entry is one inside the base prefix and outside every
  site-packages directory.

Stdlib only.
"""

from __future__ import annotations

import importlib.util
import os
import runpy
import site
import sys

_PACKAGE = "messagefoundry"


def _same(a: str, b: str) -> bool:
    return os.path.normcase(os.path.abspath(a)) == os.path.normcase(os.path.abspath(b))


def _load_this_build(package_dir: str) -> None:
    spec = importlib.util.spec_from_file_location(
        _PACKAGE,
        os.path.join(package_dir, "__init__.py"),
        submodule_search_locations=[package_dir],
    )
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load the {_PACKAGE} package at {package_dir}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[_PACKAGE] = module
    spec.loader.exec_module(module)


def _inside(path: str, parent: str) -> bool:
    path, parent = (os.path.normcase(os.path.abspath(p)) for p in (path, parent))
    try:
        return os.path.commonpath([path, parent]) == parent
    except ValueError:  # Windows: different drives
        return False


def _place_package_root() -> None:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if any(entry and _same(entry, root) for entry in sys.path):
        return
    site_dirs = [entry for entry in (*site.getsitepackages(), site.getusersitepackages()) if entry]
    bases = (sys.base_prefix, sys.base_exec_prefix)
    # On Windows without a virtual environment the base prefix is itself a site directory, and
    # the whole standard library sits inside it, so it cannot rule an entry out.
    nested_sites = [s for s in site_dirs if not any(_same(s, base) for base in bases)]

    def standard_library(entry: str) -> bool:
        return (
            any(_inside(entry, base) for base in bases)
            and not any(_same(entry, s) for s in site_dirs)
            and not any(_inside(entry, s) for s in nested_sites)
        )

    # A PYTHONPATH entry comes ahead of the standard library, and it may name a site-packages
    # directory, so the first site directory on the path can be ahead of the standard library.
    # Search for one only after the standard library's last entry (vault BACKLOG #2800).
    last_stdlib = max(
        (index for index, entry in enumerate(sys.path) if entry and standard_library(entry)),
        default=-1,
    )
    first_site = next(
        (
            index
            for index, entry in enumerate(sys.path)
            if index > last_stdlib and entry and any(_same(entry, s) for s in site_dirs)
        ),
        len(sys.path),
    )
    sys.path.insert(first_site, root)


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit("usage: python <flags> _child_bootstrap.py <module> [args...]")
    _place_package_root()
    _load_this_build(os.path.dirname(os.path.abspath(__file__)))
    module = sys.argv.pop(1)
    runpy.run_module(module, run_name="__main__", alter_sys=True)


if __name__ == "__main__":
    main()
