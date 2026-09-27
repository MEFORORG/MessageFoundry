# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The one place a command-line entry point hardens its console streams (BACKLOG #1875).

On Windows a redirected stdout or stderr takes the ANSI code page, which is cp1252 on a stock
install. stdout then raises UnicodeEncodeError on the first character cp1252 cannot encode, and
stderr writes a backslash escape in its place. Either one breaks output that carries RUNTIME data,
such as a file path the operator typed, and no scan of the source can see a value that only exists
at run time. Hardening the stream is the only control that covers that case.

Every console entry point calls :func:`harden_console_streams` at the top of ``main()``.
``tests/test_cp1252_console_safety.py`` keys its exemption on a real, imported call to this
function, found in the parsed code, so a comment or a string that names it exempts nothing.

This module imports only the standard library, so any entry point can call it cheaply.
"""

from __future__ import annotations

import contextlib
import sys

__all__ = ["harden_console_streams"]


def harden_console_streams(*, encoding: str | None = None) -> None:
    """Make ``sys.stdout`` and ``sys.stderr`` unable to raise on a character they cannot encode.

    ``errors="replace"`` always. With ``encoding=None`` each stream keeps its codec, so a character
    the codec cannot hold prints as ``?``: lossy, but it never aborts. That is the engine CLI's
    choice, because its machine-read JSON output is ASCII by construction. ``encoding="utf-8"``
    keeps every character, which is what a tool printing operator-supplied paths needs.

    Best effort by design. Some stream wrappers lack ``reconfigure`` or reject it
    (PYTHONLEGACYWINDOWSSTDIO, pytest capture, and ``None`` under ``pythonw``), and hardening must
    never itself crash the tool it protects.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        with contextlib.suppress(ValueError, OSError):
            if encoding is None:
                reconfigure(errors="replace")
            else:
                reconfigure(encoding=encoding, errors="replace")
