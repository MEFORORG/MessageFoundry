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
moves nothing. At least ``route_message``, ``route_only`` and ``transform_one`` run Routers and
Handlers without it. ``tests/test_cli_author_prints.py`` keeps every other ``redirect_stdout``,
and every other assignment to ``sys.stdout`` but the sandbox worker's, out of the package.

So stdout carries the command's result, and stderr gets what the author printed through
``sys.stdout``. Author code that writes to ``sys.__stdout__`` or file descriptor 1 directly is not
moved. Nothing redacts that text: stderr is no safer than stdout (docs/PHI.md, stream 18).

The mark is process state, not a context variable, so a load in a worker thread a command starts
is covered too. Both the mark and the redirect are counted under one lock: the first entry swaps
``sys.stdout`` and the last exit restores it, so overlapping entries in two threads cannot restore
out of order. Swapping ``sys.stdout`` is still a process-wide act, which is why the long-running
commands, whose loads run in a worker thread beside other output, are left out.
"""

from __future__ import annotations

import contextlib
import functools
import sys
import threading
from collections.abc import Callable, Iterator
from typing import TextIO

__all__ = ["author_code_stdout", "runs_author_code", "stdout_carries_a_result"]

_lock = threading.Lock()
#: How many :func:`stdout_carries_a_result` blocks are open. Marked while above zero.
_marks = 0
#: How many :func:`author_code_stdout` redirects are open, and the stream the first one replaced.
_redirects = 0
_saved_stdout: TextIO | None = None


@contextlib.contextmanager
def stdout_carries_a_result() -> Iterator[None]:
    """Mark the process as one whose stdout carries a command's result, for the block's duration."""
    global _marks
    with _lock:
        _marks += 1
    try:
        yield
    finally:
        with _lock:
            _marks -= 1


@contextlib.contextmanager
def author_code_stdout() -> Iterator[None]:
    """Enter around a run of author code: under the mark, ``print()`` goes to stderr.

    ``sys.stderr`` is read when the first redirect opens, so a stream a caller or a test installed
    is the one used."""
    global _redirects, _saved_stdout
    with _lock:
        if not _marks:
            redirected = False
        else:
            redirected = True
            if _redirects == 0:
                _saved_stdout = sys.stdout
                sys.stdout = sys.stderr
            _redirects += 1
    try:
        yield
    finally:
        if redirected:
            with _lock:
                _redirects -= 1
                if _redirects == 0 and _saved_stdout is not None:
                    sys.stdout, _saved_stdout = _saved_stdout, None


def runs_author_code[**P, R](fn: Callable[P, R]) -> Callable[P, R]:
    """Run each call of ``fn`` inside :func:`author_code_stdout`."""

    @functools.wraps(fn)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        with author_code_stdout():
            return fn(*args, **kwargs)

    return wrapper
