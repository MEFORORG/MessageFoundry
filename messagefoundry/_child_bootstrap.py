# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Start one ``messagefoundry`` module in a child process, from the build this file belongs to.

Run as a script, never imported: ``python <flags> <this file> <module> [args...]``, which is what
:func:`messagefoundry.childenv.python_child_argv` builds (vault BACKLOG #2587). The flags include
``-P``.

``-P`` keeps the working directory off the child's import path. An engine run from a source checkout
that is not installed found its own package exactly there, so the child has to be told where the
package is. This file knows: it sits inside it. It puts the package's parent directory on
``sys.path`` **after the standard library and ahead of site-packages**, then runs the module the
way ``python -m`` would.

* After the standard library, so nothing in that directory can stand in for a standard-library
  module. A ``PYTHONPATH`` entry would be searched ahead of it.
* Ahead of site-packages, so another copy of the package installed there cannot answer in the child
  when it did not in the parent.
* Not at all when the directory is already on the path, which is the installed case.

Stdlib only, and nothing here imports ``messagefoundry`` before the path is set.
"""

from __future__ import annotations

import os
import runpy
import site
import sys


def _same(a: str, b: str) -> bool:
    return os.path.normcase(os.path.abspath(a)) == os.path.normcase(os.path.abspath(b))


def _place_package_root() -> None:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if any(entry and _same(entry, root) for entry in sys.path):
        return
    site_dirs = [entry for entry in (*site.getsitepackages(), site.getusersitepackages()) if entry]
    first_site = next(
        (
            index
            for index, entry in enumerate(sys.path)
            if entry and any(_same(entry, site_dir) for site_dir in site_dirs)
        ),
        len(sys.path),
    )
    sys.path.insert(first_site, root)


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit("usage: python <flags> _child_bootstrap.py <module> [args...]")
    _place_package_root()
    module = sys.argv.pop(1)
    runpy.run_module(module, run_name="__main__", alter_sys=True)


if __name__ == "__main__":
    main()
