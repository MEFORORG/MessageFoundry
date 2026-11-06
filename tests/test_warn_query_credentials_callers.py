# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every caller of the ``warn_query_credentials`` keyword is pinned (vault BACKLOG #3766 item 4).

The keyword drops the ASVS 14.2.1 URL query-credential WARNING from one build. It is sound only
where the line was already logged for that build, by a ``build_check`` or by the runner's pre-build
step (``transports.egress.warn_url_query_credentials_before_build``). The owner ruled on 2026-11-06
to keep the public keyword rather than a ContextVar, so nothing in the type system stops a new
caller passing False with no such step before it. This census does: a call site keyed by a new
module, class, method or nested function, or a new count under one key, fails here, and whoever
adds it must show the line is logged before that build, then add it to ``_PINNED``.

What it does not catch, at least: a call moved within one function, a keyword passed through
``**kwargs``, a forwarded value whose source changed, and any caller outside the packages
:func:`tests._ast_sites.package_trees` reads. It keys on the full nested owner rather than the
outermost def, so wrapping a call in a nested helper also fails it, on purpose.
"""

from __future__ import annotations

import ast
from collections import Counter

from tests._ast_sites import package_trees

#: (module path, qualified owner, keyword value as source) -> number of calls. The owner is the
#: chain of classes and functions around the call, nested ones included. A forwarded name is the
#: caller's own keyword passed on; a literal False is a build whose line was logged before it.
_PINNED: Counter[tuple[str, str, str]] = Counter(
    {
        ("messagefoundry/pipeline/engine.py", "Engine.reload_detail", "False"): 1,
        (
            "messagefoundry/pipeline/wiring_runner.py",
            "RegistryRunner._build_fhir_lookup_executor.build",
            "False",
        ): 1,
        (
            "messagefoundry/pipeline/wiring_runner.py",
            "RegistryRunner._ensure_destination_built",
            "False",
        ): 1,
        ("messagefoundry/pipeline/wiring_runner.py", "RegistryRunner._start_outbound", "False"): 1,
        (
            "messagefoundry/pipeline/wiring_runner.py",
            "RegistryRunner.start",
            "warn_query_credentials",
        ): 2,
        (
            "messagefoundry/pipeline/wiring_runner.py",
            "RegistryRunner._reconcile_outbounds",
            "False",
        ): 3,
        ("messagefoundry/pipeline/wiring_runner.py", "RegistryRunner.reload", "False"): 1,
        ("messagefoundry/transports/base.py", "build_destination", "warn_query_credentials"): 1,
        (
            "messagefoundry/transports/fhir.py",
            "FhirLookupExecutor.__init__",
            "warn_query_credentials",
        ): 1,
    }
)

_DEFS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)


def _callers() -> Counter[tuple[str, str, str]]:
    found: Counter[tuple[str, str, str]] = Counter()

    def walk(node: ast.AST, rel: str, owner: tuple[str, ...]) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.Call):
                for kw in child.keywords:
                    if kw.arg == "warn_query_credentials":
                        found[(rel, ".".join(owner) or "<module>", ast.unparse(kw.value))] += 1
            walk(child, rel, (*owner, child.name) if isinstance(child, _DEFS) else owner)

    for rel, tree in package_trees().items():
        walk(tree, rel, ())
    return found


def test_every_warn_query_credentials_caller_is_pinned() -> None:
    found = _callers()
    assert found == _PINNED, (
        "a warn_query_credentials caller was added, moved or removed. A literal False is sound "
        "only where a build_check or the runner's pre-build warning step logged the line for this "
        "build; show that, then update _PINNED (vault BACKLOG #3766 item 4).\n"
        f"new or moved: {sorted((found - _PINNED).elements())}\n"
        f"gone: {sorted((_PINNED - found).elements())}"
    )
