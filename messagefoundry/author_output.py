# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Where a ``print()`` in an author's own code goes while a command's stdout carries its result.

The CLI runs config modules, Routers and Handlers in its own process. A debugging ``print()`` in
one wrote to stdout ahead of the command's JSON, so the document did not parse (vault BACKLOG
#1187, #2727). Wrapping each command's load one at a time left most of them uncovered, so there
is one seam with two halves (vault BACKLOG #3474):

* :func:`stdout_carries_a_result` marks the process. ``cli_common.run_cli`` enters it around the
  dispatch of every subcommand, except the ones its caller names, so a new subcommand is covered
  without anyone remembering to wrap it. The engine CLI names ``serve`` and ``supervise``
  (``_AUTHOR_PRINTS_KEEP_STDOUT`` in ``__main__.py``, which says why).
* :func:`author_code_stdout` is entered where the engine runs author code for a command: the
  config loader's ``_loading`` block (every ``load_config`` and ``validate_config``) and the
  dry-run preview's ``dry_run`` (:func:`runs_author_code`). While the mark is set it points
  ``sys.stdout`` at ``sys.stderr``; otherwise it does nothing.

**A new place that runs author code in a CLI process outside those two must enter
:func:`author_code_stdout` too**, or go through ``load_config`` or ``dry_run``. The mark alone
moves nothing. ``tests/test_cli_author_prints.py`` keeps every other ``redirect_stdout`` out of
the package, so this module stays the one place the redirect is made.

So stdout carries only the command's result, and stderr gets what the author printed. Nothing
redacts that text: stderr is no safer than stdout (docs/PHI.md, stream 18).

The mark is a module global, not a context variable, so a load in a worker thread a command starts
is covered too. Swapping ``sys.stdout`` is a process-wide act, which is why the long-running
commands, whose loads run in a worker thread beside other output, are left out.
"""

from __future__ import annotations

import contextlib
import functools
import sys
from collections.abc import Callable, Iterator

__all__ = ["author_code_stdout", "runs_author_code", "stdout_carries_a_result"]

_result_on_stdout = False


@contextlib.contextmanager
def stdout_carries_a_result() -> Iterator[None]:
    """Mark the process as one whose stdout carries a command's result, for the block's duration."""
    global _result_on_stdout
    previous = _result_on_stdout
    _result_on_stdout = True
    try:
        yield
    finally:
        _result_on_stdout = previous


def author_code_stdout() -> contextlib.AbstractContextManager[object]:
    """Enter around a run of author code: under the mark, ``print()`` goes to stderr.

    ``sys.stderr`` is read at entry, so a stream a caller or a test installed is the one used."""
    if _result_on_stdout:
        return contextlib.redirect_stdout(sys.stderr)
    return contextlib.nullcontext()


def runs_author_code[**P, R](fn: Callable[P, R]) -> Callable[P, R]:
    """Run each call of ``fn`` inside :func:`author_code_stdout`."""

    @functools.wraps(fn)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        with author_code_stdout():
            return fn(*args, **kwargs)

    return wrapper
