# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Static import-boundary guard for the sandbox worker files (ADR 0087, BACKLOG #346).

The sandbox draws its trust boundary at runtime: :class:`_ForbiddenImportFinder` (in
``_sandbox_worker``) refuses ``DEFAULT_FORBIDDEN_MODULES`` — ``socket``/``ssl``/``asyncio`` and the
I/O- and secret-bearing ``messagefoundry.*`` subpackages — but ONLY inside the ``[sandbox].mode=
subprocess`` child, which is not the default. So nothing statically pins that the two modules which
run *inside* that boundary (:mod:`messagefoundry.pipeline._sandbox_codec` and
:mod:`messagefoundry.pipeline._sandbox_worker`) do not themselves import a forbidden module. They are
clean today; a future edit that violated it would fail **only** on a deployment that turned the
sandbox on for security reasons, behind a green default-mode suite.

This is defence-in-depth test coverage, not a code fix: the guard below walks the two files' own
``ast`` import nodes and asserts none resolves under a ``DEFAULT_FORBIDDEN_MODULES`` prefix. The
forbidden set is IMPORTED from the runtime constant, never copied, so the test tracks whatever the
sandbox actually forbids. Scope is those two files' **direct** imports — deliberately not a
transitive walk: importing the codec pulls asyncio/cryptography/store/transports/auth into
``sys.modules``, so a transitive walker would be red on clean shipped code and prove nothing.
"""

from __future__ import annotations

import ast
from pathlib import Path

from messagefoundry.pipeline.sandbox import DEFAULT_FORBIDDEN_MODULES

_PIPELINE = Path(__file__).resolve().parents[1] / "messagefoundry" / "pipeline"

#: The two modules BACKLOG #346 scopes: the length-prefixed codec both ends of the pipe speak, and the
#: ``python -m`` worker child entrypoint. ``sandbox.py`` is out of that scope even though the worker
#: child also imports it (``_sandbox_worker.main`` pulls ``_read_frame_bytes``/``_write_frame`` from it,
#: before the runtime guard goes up) — it imports nothing forbidden today (stdlib + ``config.*`` + the
#: codec). A forbidden top-level import newly added to ``sandbox.py`` would evade THIS static pin (and
#: its already-bound reference would even survive the guard's ``sys.modules`` purge), so widening the
#: walk to it is a scope decision left to the owner, not a gap this two-file guard silently covers.
_TARGETS: tuple[tuple[str, Path], ...] = (
    ("messagefoundry.pipeline._sandbox_codec", _PIPELINE / "_sandbox_codec.py"),
    ("messagefoundry.pipeline._sandbox_worker", _PIPELINE / "_sandbox_worker.py"),
)


def _is_forbidden(module: str) -> bool:
    """True if ``module`` is a forbidden module or a submodule of one.

    Mirrors :meth:`_ForbiddenImportFinder.find_spec`'s prefix match by construction (``name == prefix
    or name.startswith(prefix + ".")``), so the static check agrees exactly with the runtime one."""
    return any(module == p or module.startswith(p + ".") for p in DEFAULT_FORBIDDEN_MODULES)


def _walk(source: str, dotted: str) -> tuple[set[str], int]:
    """Derive the imported dotted names from ``source`` (a module whose own name is ``dotted``).

    Returns ``(candidate module names, import-node count)``. ``ast.walk`` catches nested/function-level
    imports for free. For ``from X import a, b`` the plain module ``X`` **and** ``X.a`` / ``X.b`` are
    both candidates — the alias-append is what catches ``from messagefoundry import store`` (a
    forbidden subpackage imported off the non-forbidden ``messagefoundry`` parent). Relative imports
    are resolved to absolute against ``dotted`` so a future ``from ..store import x`` cannot walk
    straight through the guard."""
    package = dotted.rsplit(".", 1)[0]
    candidates: set[str] = set()
    node_count = 0
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            node_count += 1
            for alias in node.names:
                candidates.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            node_count += 1
            if node.level == 0:
                if node.module:
                    candidates.add(node.module)
                    for alias in node.names:
                        candidates.add(f"{node.module}.{alias.name}")
            else:
                # `from . import x` -> the package itself; `from ..store import x` -> one level up.
                base_pkg = package.rsplit(".", node.level - 1)[0]
                base = f"{base_pkg}.{node.module}" if node.module else base_pkg
                candidates.add(base)
                for alias in node.names:
                    candidates.add(f"{base}.{alias.name}")
    return candidates, node_count


def test_sandbox_boundary_modules_import_nothing_forbidden() -> None:
    """LIVE GUARD: the shipped codec + worker source imports nothing on the forbidden list.

    Green on the real source today; this pins it that way. A future ``import socket`` / ``from
    messagefoundry.store import ...`` slipping into either file would make ``mode=subprocess`` DOA on
    first deployment, and this reddens instead of the suite staying green."""
    # Anti-vacuity: the forbidden set is real and populated, so an empty scan cannot pass by default.
    assert DEFAULT_FORBIDDEN_MODULES, "DEFAULT_FORBIDDEN_MODULES is empty"
    assert "socket" in DEFAULT_FORBIDDEN_MODULES, DEFAULT_FORBIDDEN_MODULES

    violations: list[str] = []
    for dotted, path in _TARGETS:
        assert path.exists(), f"sandbox boundary module missing: {path}"
        candidates, node_count = _walk(path.read_text(encoding="utf-8"), dotted)
        # Anti-vacuity: a walker that silently saw no imports must FAIL, not pass green.
        assert node_count > 0, f"{path.name} yielded no import nodes"
        for candidate in sorted(candidates):
            if _is_forbidden(candidate):
                violations.append(f"{path.name} imports {candidate}")
    assert not violations, violations


def test_walker_flags_every_forbidden_import_form() -> None:
    """POSITIVE CONTROL: prove the walker can SEE each import form, run in isolation per form.

    Each case is its own source string so the assertion depends only on that form's handling — e.g.
    the alias-append case would still be masked by a sibling ``from messagefoundry.store import ...``
    if they shared one source, so they must not. Committed and always-on: it pins the alias-append,
    relative-resolution and nested-import refinements in CI permanently."""
    ctx = "messagefoundry.pipeline._sandbox_worker"
    cases: dict[str, tuple[str, str]] = {
        "top-level import": ("import socket\n", "socket"),
        "from-import of a forbidden submodule": (
            "from messagefoundry.store import base\n",
            "messagefoundry.store",
        ),
        # The load-bearing case: `store` is forbidden but its parent `messagefoundry` is not, so only
        # the alias-append candidate `messagefoundry.store` trips the guard here.
        "from-parent import of a forbidden child (alias-append)": (
            "from messagefoundry import store\n",
            "messagefoundry.store",
        ),
        "function-level import": ("def f():\n    import ssl\n", "ssl"),
        "relative import resolved to absolute": (
            "from ..auth import service\n",
            "messagefoundry.auth",
        ),
    }
    for label, (source, expected) in cases.items():
        candidates, node_count = _walk(source, ctx)
        assert node_count > 0, f"{label}: no import nodes seen"
        flagged = {c for c in candidates if _is_forbidden(c)}
        assert expected in flagged, f"{label}: expected {expected!r} flagged, got {sorted(flagged)}"


def test_walker_does_not_flag_allowed_imports() -> None:
    """NEGATIVE CONTROL: benign imports the sandbox child legitimately needs raise ZERO flags.

    Guards against an over-broad matcher (e.g. one that flagged the non-forbidden ``messagefoundry``
    parent), which would dead-letter a correct build — the flip side of a vacuous walker."""
    source = (
        "import json\n"
        "from messagefoundry.config.wiring import Send\n"
        "from messagefoundry.parsing.message import Message\n"
        "from messagefoundry.pipeline import _sandbox_codec\n"
    )
    candidates, node_count = _walk(source, "messagefoundry.pipeline._sandbox_worker")
    assert node_count > 0
    flagged = {c for c in candidates if _is_forbidden(c)}
    assert not flagged, sorted(flagged)
