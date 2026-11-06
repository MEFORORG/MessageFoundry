# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every caller of the ``warn_query_credentials`` keyword is pinned (vault BACKLOG #3766 item 4).

The keyword drops the ASVS 14.2.1 URL query-credential WARNING from one build. It is sound only
where the line was already logged for that build, by a ``build_check`` or by the runner's pre-build
step (``transports.egress.warn_url_query_credentials_before_build``). The owner ruled on 2026-11-06
to keep the public keyword rather than a ContextVar, so nothing in the type system stops a new
caller passing False with no such step before it. This census does: a new call site, or a moved
one, fails here, and whoever adds it must show the line is logged before that build, then add it
to ``_PINNED``.

What it does not catch, at least: a call through ``**kwargs`` or ``functools.partial``, a value
computed elsewhere and forwarded, and any caller outside ``messagefoundry/``.
"""

from __future__ import annotations

import ast
from collections import Counter
from pathlib import Path

_PKG = Path(__file__).resolve().parents[1] / "messagefoundry"

#: (module path, enclosing function, keyword value as source) -> number of calls. A forwarded name
#: is the caller's own keyword passed on; a literal False is a build whose line was logged before.
_PINNED: Counter[tuple[str, str, str]] = Counter(
    {
        ("pipeline/engine.py", "reload_detail", "False"): 1,
        ("pipeline/wiring_runner.py", "build", "False"): 1,
        ("pipeline/wiring_runner.py", "_ensure_destination_built", "False"): 1,
        ("pipeline/wiring_runner.py", "_start_outbound", "False"): 1,
        ("pipeline/wiring_runner.py", "start", "warn_query_credentials"): 2,
        ("pipeline/wiring_runner.py", "_reconcile_outbounds", "False"): 3,
        ("pipeline/wiring_runner.py", "reload", "False"): 1,
        ("transports/base.py", "build_destination", "warn_query_credentials"): 1,
        ("transports/fhir.py", "__init__", "warn_query_credentials"): 1,
    }
)


def _callers() -> Counter[tuple[str, str, str]]:
    found: Counter[tuple[str, str, str]] = Counter()

    def walk(node: ast.AST, rel: str, fn: str) -> None:
        for child in ast.iter_child_nodes(node):
            inner = child.name if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) else fn
            if isinstance(child, ast.Call):
                for kw in child.keywords:
                    if kw.arg == "warn_query_credentials":
                        found[(rel, fn, ast.unparse(kw.value))] += 1
            walk(child, rel, inner)

    for path in sorted(_PKG.rglob("*.py")):
        walk(ast.parse(path.read_text(encoding="utf-8")), path.relative_to(_PKG).as_posix(), "")
    return found


def test_every_warn_query_credentials_caller_is_pinned() -> None:
    found = _callers()
    # The walk's own floor: a moved package or a broken glob would find nothing and pass.
    assert sum(found.values()) >= sum(_PINNED.values())
    assert found == _PINNED, (
        "a warn_query_credentials caller was added, moved or removed. A literal False is sound "
        "only where a build_check or the runner's pre-build warning step logged the line for this "
        "build; show that, then update _PINNED (vault BACKLOG #3766 item 4).\n"
        f"new or moved: {sorted((found - _PINNED).elements())}\n"
        f"gone: {sorted((_PINNED - found).elements())}"
    )
