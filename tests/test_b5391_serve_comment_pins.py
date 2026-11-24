# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5391 item 1, S19-73 and S19-74: two comments in ``serve`` that stated false things.

Both were corrected by engine PR 3019. These pins read ``_serve``'s own source, so a revert of
either comment fails here.

* S19-73: the comment above ``_serve``'s ``install_remote_debug_guard()`` call said the hook was
  not first in the process and that the window before it "stays open". The module-level call
  (vault BACKLOG #2742) puts the hook in before the module's other imports and argument parsing;
  ``tests/test_remote_debug_guard.py`` pins that order. The finding's second half, function-local
  re-imports of ``sys`` and ``Path`` in ``_serve``, was already gone before PR 3019, so the AST
  pin below passes on that code too and only guards against a return.
* S19-74: a comment justified the loopback arm of the declared-proxy gate by the upgrade breakage
  it would cause on working deployments. There are none (``CLAUDE.md`` section 0); the reason is
  that a refusal there would also stop the recommended topology.
"""

from __future__ import annotations

import ast
import inspect
import textwrap

from messagefoundry.__main__ import _serve


def _serve_source() -> str:
    # unwrap: _serve carries the pre-lifespan anchor audit hook (functools.wraps).
    return inspect.getsource(inspect.unwrap(_serve))


def test_s19_73_the_guard_comment_does_not_say_the_window_stays_open() -> None:
    src = _serve_source()
    assert "window stays open" not in src
    assert "NOT first in the process" not in src


def test_s19_73_serve_does_not_re_import_sys_or_path() -> None:
    tree = ast.parse(textwrap.dedent(_serve_source()))
    local = [
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import | ast.ImportFrom)
        and (getattr(node, "module", None) in (None, "pathlib"))
        for alias in node.names
        if alias.name in ("sys", "Path")
    ]
    assert local == [], f"_serve re-imports names the module already binds: {local}"


def test_s19_74_no_serve_comment_cites_upgrade_breakage_on_working_deployments() -> None:
    src = _serve_source()
    assert "working deployments on upgrade" not in src
    assert "hard-stop" not in src
