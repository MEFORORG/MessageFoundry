# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Keep the two top-level ``conftest`` modules unreachable by bare name (BACKLOG #1255).

``testpaths`` names two roots and BOTH ship a ``conftest.py``; neither root is a package and nothing
selects an import mode, so pytest runs its default ``prepend`` and both files claim the same
importable name, ``conftest``. In a run that collects both trees only one wins ``sys.modules``.

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

**WHY A GUARD RATHER THAN A STRUCTURAL FIX.** All three structural options have now been measured
against this tree and every one is worse than the status quo. **This guard is the fix, not a
placeholder for one** -- that is what closed BACKLOG #1255 on 2026-09-10:

* ``__init__.py`` in BOTH roots is the option BACKLOG #1255 recommends, and it does not work. Both
  directories are named ``tests``, so both conftests become ``tests.conftest`` -- the collision does
  not go away, it moves up one level and turns fatal. Measured in a scratch sandbox with this
  topology: ``_pytest.pathlib.ImportPathMismatchError``, and **the whole suite fails to collect.**
* ``__init__.py`` in the root tree ONLY leaves the mis-bind in place: the root tree's bare import
  then resolves to the web tree's module every time, rather than by collection order.
* ``--import-mode=importlib`` DOES remove the collision -- a bare ``import conftest`` becomes a
  clean ``ModuleNotFoundError``. **It was the one option left open, and it is now MEASURED AND
  REJECTED.** It breaks collection: not on the ``from tests.X import ...`` files #1255 predicted
  (zero of those failed), but on **bare SIBLING imports of helper modules inside a test root**
  (``import _totp_clock``), which work only because ``prepend`` puts the test root ITSELF on
  ``sys.path``. Worse, the failing set is **order-dependent** -- one unrelated module does
  ``sys.path.insert`` at import time, so which files break depends on collection order, and CI runs
  across processes.

**The full measurement -- both-testpaths counts, the two-armed control, the ini-key trap, and every
figure quoted above -- is recorded ONCE, in the closing record of BACKLOG #1255. Read it there.**
This docstring carries the DECISION and what would re-open it; the row carries the evidence. Do not
copy the numbers back here, and do not re-run the measurement (the row says so too).

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
from typing import Any

import pytest

from tests._workflow_contexts import ROOT

#: The scan is worthless if it silently walks an empty tree, so it asserts it saw at least this many
#: import statements overall. Far below the real figure (8666 at the time of writing) -- this is a
#: liveness floor for the walker, not a pinned count that rots on every added import.
_MIN_IMPORT_STATEMENTS = 500


@dataclass(frozen=True)
class _Scan:
    """What the walk found, plus enough about HOW it walked to tell a null from a dead instrument."""

    findings: tuple[str, ...]
    files_by_root: tuple[tuple[str, int], ...]
    import_statements: int
    #: ``(importer, helper)`` for every bare import of a module that is importable ONLY because
    #: ``prepend`` puts the test root itself on ``sys.path``. The premise behind rejecting importlib.
    sibling_imports: tuple[tuple[str, str], ...]


@cache
def _pytest_ini() -> dict[str, Any]:
    """``[tool.pytest.ini_options]``, read from disk once per process."""
    cfg = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    options: dict[str, Any] = cfg["tool"]["pytest"]["ini_options"]
    return options


def _testpath_roots() -> tuple[Path, ...]:
    """Read the roots from ``pyproject.toml`` rather than hard-coding them.

    A third testpath added tomorrow ships a third top-level ``conftest.py`` candidate, and this guard
    has to cover it without anyone remembering to widen a literal here.
    """
    testpaths: list[str] = _pytest_ini()["testpaths"]
    return tuple(ROOT / p for p in testpaths)


def _import_statements(tree: ast.Module) -> list[ast.Import | ast.ImportFrom]:
    """Every import STATEMENT in ``tree``, relative ones included.

    Separate from the head extraction below because the two counts are different questions and one
    does not derive from the other: ``import a, b`` is ONE statement binding TWO heads, and a
    relative import is a statement that binds no head this file may judge.
    """
    return [n for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))]


def _heads_of(nodes: list[ast.Import | ast.ImportFrom]) -> list[tuple[int, str, str]]:
    """``(lineno, bound top-level name, rendered)`` for the ABSOLUTE imports among ``nodes``."""
    heads: list[tuple[int, str, str]] = []
    for node in nodes:
        if isinstance(node, ast.Import):
            heads += [(node.lineno, a.name.split(".")[0], f"import {a.name}") for a in node.names]
        elif node.level == 0 and node.module is not None:
            head = node.module.split(".")[0]
            heads.append((node.lineno, head, f"from {node.module} import ..."))
    return heads


def absolute_import_heads(tree: ast.Module) -> list[tuple[int, str, str]]:
    """Return ``(lineno, bound top-level name, rendered)`` for every ABSOLUTE import in ``tree``.

    **The one place the exemption rule lives**, because both guards in this file need exactly the
    same one and encoding it twice would let a fix to either silently skip the other. Relative
    imports (``from . import conftest``) are unambiguous -- they resolve against the importing
    module's own package -- so ``node.level > 0`` is deliberately excluded. The *head* is what an
    import BINDS, so ``import a.b`` and ``from a.b import c`` both report ``a``: that is the name
    resolved off ``sys.path``, and it is the only part either guard is entitled to judge.

    ``_scan`` does not call this -- it needs the statement count from the same pass, and walking
    ~830 files twice to get both cost a measured 19 percent of the scan. This is the single-tree
    entry point the control tests use.
    """
    return _heads_of(_import_statements(tree))


def bare_conftest_imports(tree: ast.Module) -> list[tuple[int, str]]:
    """Return ``(lineno, rendered)`` for every import binding the top-level name ``conftest``.

    ``from tests.conftest import ...`` binds ``tests``, not ``conftest``, so it is not a finding --
    package-qualified is exactly the shape this guard steers to.
    """
    return [
        (lineno, what) for lineno, head, what in absolute_import_heads(tree) if head == "conftest"
    ]


def _root_local_module_names(root: Path) -> frozenset[str]:
    """Top-level names importable ONLY because pytest's ``prepend`` puts ``root`` on ``sys.path``.

    That is every ``*.py`` sitting directly in the root plus every package directory in it. Under
    ``--import-mode=importlib`` pytest inserts nothing, so a bare import of one of these raises.
    """
    names = {p.stem for p in root.glob("*.py")}
    names |= {d.name for d in root.iterdir() if d.is_dir() and (d / "__init__.py").exists()}
    return frozenset(names)


def sibling_bare_imports(tree: ast.Module, local: frozenset[str]) -> list[str]:
    """Return the helper names this module imports bare from its own test root.

    ``conftest`` is not special-cased out: a bare ``import conftest`` is genuinely one of the imports
    importlib would break, and the dedicated guard above reds on it separately anyway.
    """
    return [head for _, head, _ in absolute_import_heads(tree) if head in local]


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
    sibling_imports: set[tuple[str, str]] = set()
    import_statements = 0
    for root in _testpath_roots():
        count = 0
        local = _root_local_module_names(root)
        for py in sorted(root.rglob("*.py")):
            count += 1
            rel = py.relative_to(ROOT).as_posix()
            # ONE walk, every verdict: the liveness count AND both guards' findings. Each extra
            # ast.walk over these ~830 files costs a measured ~0.75s CPU, and the heads are just a
            # projection of the statements, so re-walking to get them is paying twice for one pass.
            nodes = _import_statements(_parse(py))
            import_statements += len(nodes)
            heads = _heads_of(nodes)
            findings += [
                f"{rel}:{lineno}: {what}" for lineno, head, what in heads if head == "conftest"
            ]
            sibling_imports |= {(rel, head) for _, head, _ in heads if head in local}
        files_by_root.append((root.relative_to(ROOT).as_posix(), count))
    return _Scan(
        tuple(findings), tuple(files_by_root), import_statements, tuple(sorted(sibling_imports))
    )


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


def test_every_pytest_ini_key_is_a_registered_option(pytestconfig: pytest.Config) -> None:
    """An unregistered ini key only WARNS, so a dead setting reads exactly like a live one.

    BACKLOG #1255 reached for ``importmode = "importlib"``. There is no such ini option --
    ``--import-mode`` is registered with ``group.addoption``, never ``addini`` -- so pytest emits
    ``PytestConfigWarning: Unknown config option`` and runs in the DEFAULT mode anyway. The row
    records the measured no-op.

    **Pinning that one spelling would have been the shallow fix**: a reader translating
    ``--import-mode`` into ini form is at least as likely to write ``import_mode`` or
    ``import-mode``, which fail the same silent way. ``Config.getini`` raises for any key never
    passed to ``addini``, so asking the live config about EVERY key covers the whole class, and
    covers plugin-registered keys too.
    """
    unknown = []
    for key in _pytest_ini():
        try:
            pytestconfig.getini(key)
        except ValueError:
            unknown.append(key)
    assert not unknown, (
        f"`[tool.pytest.ini_options]` carries {unknown}, which pytest does not recognise. It warns "
        "and then runs its DEFAULTS, so the setting reads as chosen while doing nothing. If one of "
        "these is a command-line option, spell it in `addopts` instead -- and if it is "
        "`--import-mode`, read this module's docstring first: importlib is measured and rejected."
    )


def test_the_unknown_ini_key_detector_actually_rejects_something(
    pytestconfig: pytest.Config,
) -> None:
    """POSITIVE CONTROL. A ``getini`` that raised for nothing would pass the guard above silently."""
    with pytest.raises(ValueError, match="unknown configuration value"):
        pytestconfig.getini("importmode")


def test_the_sibling_bare_imports_that_rule_out_importlib_are_still_present() -> None:
    """PREMISE PIN for the REJECTION, the mirror of the premise pin below (BACKLOG #1255).

    importlib mode is rejected because these helpers are importable only while ``prepend`` puts each
    test root on ``sys.path``. **The count is deliberately not pinned** -- it moves with every added
    helper, and a pinned number would red on healthy change. What is pinned is that the population is
    NON-EMPTY, because the day it empties, importlib stops breaking collection and becomes
    re-priceable. The population as measured is in #1255's closing record, not repeated here.

    **THIS IS NOT A BILL FOR DOING THE RECOMMENDED THING.** Emptying the population means migrating
    ``import _totp_clock`` to ``from tests._totp_clock import ...`` -- the house idiom this module
    steers to. That migration is welcome; it just also re-prices a closed row, so this pin makes it
    say so out loud rather than leaving a rejection standing on a premise that quietly expired.
    """
    scan = _scan()
    assert scan.sibling_imports, (
        "no module under a testpath root imports a root-local helper by bare name any more. NOTHING "
        "IS WRONG and this is not asking you to undo it -- package-qualified is the idiom this file "
        "recommends. But it is the premise behind REJECTING `--import-mode=importlib`, so re-price "
        "that rejection against BACKLOG #1255 and retire this pin, rather than restoring a bare "
        "import to make the test green."
    )


def test_the_sibling_detector_separates_the_two_import_shapes() -> None:
    """POSITIVE AND NEGATIVE CONTROL. The rejection rests on this detector telling them apart."""
    local = frozenset({"_totp_clock", "adr0075_batch_harness"})
    planted = ast.parse(
        "import _totp_clock\nfrom adr0075_batch_harness import run\nimport _totp_clock.sub\n"
    )
    # Sorted, not source order: ``ast.walk`` is breadth-first, so ordering here would pin the
    # walker's traversal rather than the detector's verdict.
    assert sorted(sibling_bare_imports(planted, local)) == [
        "_totp_clock",
        "_totp_clock",
        "adr0075_batch_harness",
    ]

    # The shapes that survive importlib and must NOT be counted: package-qualified resolves off the
    # project root (measured clean under importlib), and a relative import carries its own anchor.
    allowed = ast.parse(
        "from tests._totp_clock import x\nfrom . import _totp_clock\nimport totp_clock\n"
    )
    assert sibling_bare_imports(allowed, local) == []


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
