# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Read a login leg's ``mfa_verified`` grant off its SOURCE (ASVS 6.3.4 / 6.8.4).

Two suites assert on the same fact from different angles -- ``tests/test_mfa_access_gate.py`` pins the
behaviour and ``tests/test_docs_security_pathways.py`` pins the disclosure in ``docs/SECURITY.md``
against it -- so the reading lives here rather than being written twice. Both copies existed briefly
and had to be flipped together when BACKLOG #1144 retired the delegated-directory relaxation; the next
change to a grant would have been free to leave one file green and the other red.

**Why source and not behaviour.** The grant is a literal at one call site. Driving a live SPNEGO
exchange to observe it would let a fixture that happens to take an early-return path satisfy the
assertion without the grant ever being evaluated -- an instrument answering the adjacent question.
Callers pair this with a behavioural test rather than relying on it alone.
"""

from __future__ import annotations

import ast
import inspect
import textwrap
from typing import Any

__all__ = ["mfa_grant_values"]


def mfa_grant_values(func: Any) -> list[ast.expr]:
    """Every expression passed as ``mfa_verified=`` inside ``func``'s source, in source order.

    An empty list means the seam moved -- the leg passes no such keyword at all -- which callers must
    treat as a failure rather than as "no constant found", or the assertion passes vacuously.
    """
    tree = ast.parse(textwrap.dedent(inspect.getsource(func)))
    return [
        kw.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        for kw in node.keywords
        if kw.arg == "mfa_verified"
    ]
