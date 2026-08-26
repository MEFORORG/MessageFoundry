# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Keep the two top-level ``conftest`` modules unreachable by bare name (BACKLOG #1255).

``testpaths`` names two roots and BOTH ship a ``conftest.py``; neither root is a package and
``pyproject.toml`` sets no ``importmode``, so pytest runs its default ``prepend`` and both files
claim the same importable name, ``conftest``. In a run that collects both trees only one wins
``sys.modules``.

**THE TRAP IS SILENT, NOT LOUD, WHICH IS WHY IT EARNS A GUARD RATHER THAN A COMMENT.** The two
conftests duplicate the logging-quiesce machinery, so they share top-level names and a mis-bound
``import conftest`` does not necessarily raise -- it can SUCCEED and hand back the wrong tree's
implementation. Measured by AST over both files: **10 shared top-level names counting module-level
constants, 8 counting only defs and classes.** (BACKLOG #1255 records 8; the two figures agree on
the same population and differ only in whether ``_ABOVE_CRITICAL`` and ``_QUIESCE_TARGETS`` count,
so the narrower rule is the item's, not a stale reading.)

Demonstrated on these real trees, not only in the abstract: with a bare ``import conftest`` planted
in ``tests/`` and both testpaths collected together, collection succeeded with no error and
``sys.modules["conftest"]`` resolved to the WEB tree's file.

**WHY A GUARD RATHER THAN A STRUCTURAL FIX.** The two package-marker options were measured against
this tree and both are worse than the status quo; the import-mode option is unresolved rather than
rejected:

* ``__init__.py`` in BOTH roots is the option BACKLOG #1255 recommends, and it does not work. Both
  directories are named ``tests``, so both conftests become ``tests.conftest`` -- the collision does
  not go away, it moves up one level and turns fatal. Measured in a scratch sandbox with this
  topology: ``_pytest.pathlib.ImportPathMismatchError``, and **the whole suite fails to collect.**
* ``__init__.py`` in the root tree ONLY leaves the mis-bind in place: the root tree's bare import
  then resolves to the web tree's module every time, rather than by collection order.
* ``importmode = "importlib"`` DOES remove the collision -- a bare ``import conftest`` becomes a
  clean ``ModuleNotFoundError``. It is not taken here because its cost is **unmeasured against this
  tree**, not because it was shown to break: 44 files under these two roots import the ``tests``
  package, INCLUDING ``tests/conftest.py`` itself. #1255 states that importlib mode does not put
  rootdir on ``sys.path`` and would therefore break them; **that did not reproduce on pytest 9.1.1**
  (a ``from tests.X import ...`` resolved under importlib in the sandbox, with and without
  ``pythonpath``, under the bare ``pytest`` entry point as well as ``python -m pytest``). One
  trivial helper in a sandbox is not 44 real files, so the honest status is that the item's stated
  risk needs re-measuring on this tree before anyone adopts or dismisses the option. Switching the
  import semantics of 691 files on an unreproduced premise is the change this guard exists to avoid
  needing.

So the cheap, correct move is to keep the module name unreachable. That is already the house idiom
-- shared helpers live in named modules imported package-qualified (``tests/_workflow_contexts.py``,
imported as ``from tests._workflow_contexts import ...``) -- and this file makes the idiom
enforceable instead of customary.

**DO NOT "FIX" A FUTURE VIOLATION BY IMPORTING ``conftest`` BY PATH.** ``tests/conftest.py`` claims
a per-process test slot and registers an ``atexit`` unlink, so importing it a second time under
another name has side effects. Move the helper into a named module instead.

**AST, NOT ``grep``.** An earlier attempt to census these names with ``grep -oP`` died on this box's
locale and printed nothing, which is indistinguishable from a clean result. The scan below parses,
and pairs its null with a positive control, for the same reason.
"""

from __future__ import annotations

import ast
import tomllib
import warnings
from dataclasses import dataclass
from functools import cache
from pathlib import Path

from tests._workflow_contexts import ROOT

#: The scan is worthless if it silently walks an empty tree, so it asserts it saw at least this many
#: import statements overall. Far below the real figure (7121 at the time of writing) -- this is a
#: liveness floor for the walker, not a pinned count that rots on every added import.
_MIN_IMPORT_STATEMENTS = 500


@dataclass(frozen=True)
class _Scan:
    """What the walk found, plus enough about HOW it walked to tell a null from a dead instrument."""

    findings: tuple[str, ...]
    files_by_root: tuple[tuple[str, int], ...]
    import_statements: int


def _testpath_roots() -> tuple[Path, ...]:
    """Read the roots from ``pyproject.toml`` rather than hard-coding them.

    A third testpath added tomorrow ships a third top-level ``conftest.py`` candidate, and this guard
    has to cover it without anyone remembering to widen a literal here.
    """
    cfg = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    testpaths: list[str] = cfg["tool"]["pytest"]["ini_options"]["testpaths"]
    return tuple(ROOT / p for p in testpaths)


def bare_conftest_imports(tree: ast.Module) -> list[tuple[int, str]]:
    """Return ``(lineno, rendered)`` for every import binding the top-level name ``conftest``.

    Relative imports (``from . import conftest``) are unambiguous -- they resolve against the
    importing module's own package -- so ``node.level > 0`` is deliberately not a finding. Nor is
    ``from tests.conftest import ...``: package-qualified is exactly the shape this guard steers to.
    """
    hits: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "conftest" or alias.name.startswith("conftest."):
                    hits.append((node.lineno, f"import {alias.name}"))
        elif (
            isinstance(node, ast.ImportFrom)
            and node.level == 0
            and node.module is not None
            and (node.module == "conftest" or node.module.startswith("conftest."))
        ):
            hits.append((node.lineno, f"from {node.module} import ..."))
    return hits


def _parse(path: Path) -> ast.Module:
    # A scanned file's own SyntaxWarning (invalid escape sequences live in at least one test module)
    # is that file's business, not this guard's -- it must not colour this run.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


@cache
def _scan() -> _Scan:
    findings: list[str] = []
    files_by_root: list[tuple[str, int]] = []
    import_statements = 0
    for root in _testpath_roots():
        count = 0
        for py in sorted(root.rglob("*.py")):
            count += 1
            tree = _parse(py)
            import_statements += sum(
                1 for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))
            )
            for lineno, what in bare_conftest_imports(tree):
                findings.append(f"{py.relative_to(ROOT).as_posix()}:{lineno}: {what}")
        files_by_root.append((root.relative_to(ROOT).as_posix(), count))
    return _Scan(tuple(findings), tuple(files_by_root), import_statements)


def _importable_name(conftest: Path) -> str:
    """The top-level module name pytest's ``prepend`` mode would give this file.

    Prepend walks up from the file while each directory is a package, then inserts the first
    non-package ancestor on ``sys.path``. So a ``conftest.py`` in a non-package directory is simply
    ``conftest``, and two of those collide.
    """
    parts = [conftest.stem]
    parent = conftest.parent
    while (parent / "__init__.py").exists():
        parts.append(parent.name)
        parent = parent.parent
    return ".".join(reversed(parts))


def test_no_module_under_a_testpath_imports_conftest_by_bare_name() -> None:
    """THE GUARD. Reintroducing the bare import arms the collision, so it reds here."""
    scan = _scan()
    assert not scan.findings, (
        "A bare `import conftest` binds to whichever testpath root pytest loaded first, and the two "
        "conftests share top-level names, so this can succeed and return the WRONG tree's "
        "implementation. Move the helper into a named module and import it package-qualified "
        "(see tests/_workflow_contexts.py). Offenders:\n  " + "\n  ".join(scan.findings)
    )


def test_the_detector_trips_on_a_planted_bare_import() -> None:
    """POSITIVE CONTROL. Without it, a dead detector reads exactly like a clean tree."""
    planted = ast.parse(
        "import conftest\nfrom conftest import _Baseline\nfrom conftest.sub import x\n"
    )
    assert len(bare_conftest_imports(planted)) == 3

    # NEGATIVE CONTROL: the shapes that must NOT be findings, or the guard would forbid the very
    # idiom it is steering people towards.
    allowed = ast.parse(
        "from tests.conftest import x\nimport conftesting\nfrom . import conftest\n"
    )
    assert bare_conftest_imports(allowed) == []


def test_the_scan_reached_every_testpath_root() -> None:
    """SCOPE CONTROL. A walk that visited nothing returns the same empty findings as a clean tree."""
    scan = _scan()
    roots = dict(scan.files_by_root)
    assert set(roots) == {r.relative_to(ROOT).as_posix() for r in _testpath_roots()}
    for name, count in roots.items():
        assert count > 0, f"scanned zero files under {name}; the guard proved nothing"
    assert scan.import_statements >= _MIN_IMPORT_STATEMENTS, (
        f"only {scan.import_statements} import statements seen across {roots}; the walker is not "
        "reading these files, so its empty findings mean nothing"
    )


def test_the_collision_that_makes_this_guard_necessary_is_still_present() -> None:
    """PREMISE PIN. When this reds, the guard has become re-priceable -- read the module docstring.

    It fails in exactly one direction that matters: someone lands a structural change and the two
    conftests stop claiming one name. That is good news, not a defect, and the guard can then be
    retired rather than quietly kept on as decoration.
    """
    names = [
        _importable_name(root / "conftest.py")
        for root in _testpath_roots()
        if (root / "conftest.py").exists()
    ]
    assert len(names) >= 2, (
        f"only {len(names)} testpath root(s) ship a conftest.py ({names}), so two of them can no "
        "longer claim one module name. Nothing is wrong here -- the premise behind this guard "
        "changed, so re-price it against BACKLOG #1255 rather than leaving it in place unexplained."
    )
    assert len(set(names)) < len(names), (
        f"the testpath conftests now resolve to distinct module names {names}, so the bare-name "
        "collision this guard exists for is gone. Re-price the guard against BACKLOG #1255 rather "
        "than leaving it in place unexplained."
    )
