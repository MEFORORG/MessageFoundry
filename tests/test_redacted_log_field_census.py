# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The call-site census for ``logging_setup.redacted_log_field`` (vault BACKLOG #3770 step 7).

What a ``redacted_log_field`` caller passes as ``before``, ``after`` and ``checks`` decides what
the logged field hides, and only the caller's own hides-no-less-than-main test shows that a
choice is safe. So this pins, by an AST walk of the shipped packages, each reference it finds by
name to ``redacted_log_field``, to ``redact_log_value`` (which takes no ``checks``) and to
``controlchars.log_field_token`` (which redacts nothing), and fails on:

- a new reference, a call or not, so a new caller arrives here with its own test named below;
- an import of any of the three under another name, which a walk by name would miss;
- a ``before`` or ``after`` that is not a string literal or a module-level constant built only
  from literals and other such constants, since caller text there can leave readable what the
  shipped filters would redact. A name counts as a constant only when the file binds it once, by
  one plain module-level assignment: a parameter, a local, a loop, ``with``, ``except`` or
  ``match`` target, a walrus, an import, a ``def``, a tuple target, an augmented assignment or a
  ``global`` declaration of that name anywhere in the file disqualifies it;
- a pinned caller whose named test module holds no ``test_`` function that calls it. That
  proves a test exercises the caller, not that the test compares what it hides with main; the
  reviewer of a new pin reads that.

The walk reads names, so it misses at least a reference reached through ``getattr`` with a
computed name, or through a module object passed around, and a constant rebound from another
module, through ``globals()`` or by ``setattr``; the negative controls below show what
it does catch. Synthetic code only.
"""

from __future__ import annotations

import ast
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import pytest

from messagefoundry import logging_setup

_ROOT = Path(__file__).resolve().parents[1]

#: The shipped packages: the engine, the toolkit, the web console and the harness.
_PACKAGES = ("messagefoundry", "messagefoundry_toolkit", "messagefoundry_webconsole", "harness")

_WATCHED = frozenset({"redacted_log_field", "redact_log_value", "log_field_token"})

#: The callees whose ``before`` and ``after`` are read for a non-constant value.
_CONTEXT_CALLEES = frozenset({"redacted_log_field", "redact_log_value"})


@dataclass(frozen=True, order=True)
class _Reference:
    path: str
    enclosing: str
    name: str
    is_call: bool


#: Every production reference, with how many times each occurs. A new one fails the census; it
#: is added here only with the caller's own hides-no-less-than-main test in
#: :data:`_CALLER_TESTS`.
_PINNED: Counter[_Reference] = Counter(
    {
        _Reference(
            "messagefoundry/auth/service.py", "_new_ip_path_field", "redacted_log_field", True
        ): 1,
        _Reference(
            "messagefoundry/logging_setup.py", "redacted_log_field", "redact_log_value", True
        ): 1,
        _Reference(
            "messagefoundry/logging_setup.py", "redacted_log_field", "log_field_token", True
        ): 2,
    }
)

#: The functions inside the census itself: ``redacted_log_field`` hands its own ``before`` and
#: ``after`` to ``redact_log_value``, so its call is a pass-through, not a choice of context.
_PASS_THROUGH = frozenset({("messagefoundry/logging_setup.py", "redacted_log_field")})

#: Each production caller of ``redacted_log_field`` and the test module holding its
#: hides-no-less-than-main test, which must name it.
_CALLER_TESTS = {
    ("messagefoundry/auth/service.py", "_new_ip_path_field"): "tests/test_admin_new_ip.py"
}


@dataclass(frozen=True)
class _Finding:
    path: str
    line: int
    what: str


def _enclosing_names(tree: ast.Module) -> dict[ast.AST, str]:
    """Each node's innermost enclosing function or class, dotted, or ``<module>``."""
    owner: dict[ast.AST, str] = {}

    def visit(node: ast.AST, name: str) -> None:
        for child in ast.iter_child_nodes(node):
            child_name = name
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                child_name = child.name if name == "<module>" else f"{name}.{child.name}"
            owner[child] = child_name
            visit(child, child_name)

    visit(tree, "<module>")
    return owner


def _bindings(tree: ast.Module) -> Counter[str]:
    """How many times the file binds each name, anywhere: a store, a parameter, an import, a
    ``def`` or ``class``, an ``except`` or ``match`` capture, or a ``global`` declaration."""
    bound: Counter[str] = Counter()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            bound[node.id] += 1
        elif isinstance(node, ast.arg):
            bound[node.arg] += 1
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                bound[alias.asname or alias.name.split(".", 1)[0]] += 1
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound[node.name] += 1
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            bound.update(node.names)
        elif (
            isinstance(node, ast.ExceptHandler)
            and node.name
            or isinstance(node, (ast.MatchAs, ast.MatchStar))
            and node.name
        ):
            bound[node.name] += 1
        elif isinstance(node, ast.MatchMapping) and node.rest:
            bound[node.rest] += 1
    return bound


def _module_constants(tree: ast.Module) -> dict[str, ast.expr]:
    """Module-level ``NAME = value`` and ``NAME: T = value`` bindings, by name, of the names the
    file binds nowhere else."""
    bound = _bindings(tree)
    found: dict[str, ast.expr] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name):
                found[target.id] = node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            if isinstance(node.target, ast.Name):
                found[node.target.id] = node.value
    return {name: value for name, value in found.items() if bound[name] == 1}


def _is_constant_text(expr: ast.expr, constants: dict[str, ast.expr], seen: frozenset[str]) -> bool:
    """Whether ``expr`` is built only from literals and module constants that are themselves so
    built: a literal, an f-string or ``+`` over such parts, or a name bound to one. No call, no
    attribute, no subscript."""
    if isinstance(expr, ast.Constant):
        return isinstance(expr.value, (str, int))
    if isinstance(expr, ast.JoinedStr):
        return all(_is_constant_text(part, constants, seen) for part in expr.values)
    if isinstance(expr, ast.FormattedValue):
        return expr.format_spec is None and _is_constant_text(expr.value, constants, seen)
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        return _is_constant_text(expr.left, constants, seen) and _is_constant_text(
            expr.right, constants, seen
        )
    if isinstance(expr, ast.Name) and expr.id in constants and expr.id not in seen:
        return _is_constant_text(constants[expr.id], constants, seen | {expr.id})
    return False


def _census(path: str, source: str) -> tuple[list[_Reference], list[_Finding]]:
    """The watched references in ``source`` and what the census refuses there."""
    tree = ast.parse(source, filename=path)
    owner = _enclosing_names(tree)
    constants = _module_constants(tree)
    references: list[_Reference] = []
    findings: list[_Finding] = []
    calls = {id(node.func): node for node in ast.walk(tree) if isinstance(node, ast.Call)}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if alias.name.rsplit(".", 1)[-1] in _WATCHED and alias.asname not in (
                    None,
                    alias.name.rsplit(".", 1)[-1],
                ):
                    findings.append(
                        _Finding(path, node.lineno, f"{alias.name} imported as {alias.asname}")
                    )
            continue
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            name = node.id
        elif isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
            name = node.attr
        else:
            continue
        if name not in _WATCHED:
            continue
        enclosing = owner.get(node, "<module>")
        call = calls.get(id(node))
        references.append(_Reference(path, enclosing, name, call is not None))
        if call is None or name not in _CONTEXT_CALLEES or (path, enclosing) in _PASS_THROUGH:
            continue
        for keyword in call.keywords:
            if keyword.arg in ("before", "after") and not _is_constant_text(
                keyword.value, constants, frozenset()
            ):
                findings.append(
                    _Finding(path, call.lineno, f"{name}({keyword.arg}=...) is not a constant")
                )
            if keyword.arg is None:
                findings.append(_Finding(path, call.lineno, f"{name}(**...) hides its context"))
    return references, findings


def _shipped_sources() -> list[tuple[str, str]]:
    sources = []
    for package in _PACKAGES:
        for file in sorted((_ROOT / package).rglob("*.py")):
            sources.append((file.relative_to(_ROOT).as_posix(), file.read_text(encoding="utf-8")))
    return sources


def test_the_census_reads_a_known_tree() -> None:
    # Positive control: the walk must see the files it pins, or a pin set it never compares
    # against passes empty.
    paths = {path for path, _ in _shipped_sources()}
    assert {reference.path for reference in _PINNED} <= paths


def test_every_production_reference_is_pinned_and_takes_constant_context() -> None:
    references: Counter[_Reference] = Counter()
    findings: list[_Finding] = []
    for path, source in _shipped_sources():
        found, refused = _census(path, source)
        references.update(found)
        findings.extend(refused)
    assert findings == []
    assert references == _PINNED, (
        "a reference to redacted_log_field, redact_log_value or log_field_token was added or "
        "removed; pin it here with the caller's own hides-no-less-than-main test in _CALLER_TESTS"
    )


@pytest.mark.parametrize(("caller", "test_module"), sorted(_CALLER_TESTS.items()))
def test_each_pinned_caller_has_its_own_hides_no_less_than_main_test(
    caller: tuple[str, str], test_module: str
) -> None:
    path, function = caller
    assert any(
        reference.path == path
        and reference.enclosing == function
        and reference.name == "redacted_log_field"
        for reference in _PINNED
    )
    source = (_ROOT / test_module).read_text(encoding="utf-8")
    assert _test_functions_calling(source, function), (
        f"{test_module} holds no test_ function that calls {function}"
    )


def _test_functions_calling(source: str, function: str) -> list[str]:
    """The ``test_`` functions in ``source`` whose body calls ``function`` by name."""
    found = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith(
            "test_"
        ):
            for inner in ast.walk(node):
                if (
                    isinstance(inner, ast.Call)
                    and isinstance(inner.func, ast.Name)
                    and inner.func.id == function
                ):
                    found.append(node.name)
                    break
    return found


def test_a_caller_test_module_that_only_imports_the_caller_is_refused() -> None:
    """NEGATIVE CONTROL: a module that imports or mentions the caller, with no test calling it,
    passed the check when it read the module's text for the name."""
    source = (
        "from messagefoundry.auth.service import _new_ip_path_field\n"
        "# _new_ip_path_field is named here\n"
        "def test_other():\n    assert True\n"
        "def helper():\n    return _new_ip_path_field('/a')\n"
    )
    assert _test_functions_calling(source, "_new_ip_path_field") == []
    assert _test_functions_calling(
        source + "def test_it():\n    assert _new_ip_path_field('/a')\n", "_new_ip_path_field"
    ) == ["test_it"]


def test_every_caller_of_redacted_log_field_is_in_the_caller_test_map() -> None:
    callers = {
        (reference.path, reference.enclosing)
        for reference in _PINNED
        if reference.name == "redacted_log_field"
    }
    assert callers == set(_CALLER_TESTS)


# --- negative controls: what the census refuses ------------------------------------------------


def test_the_census_sees_a_new_caller() -> None:
    source = (
        "from messagefoundry.logging_setup import redacted_log_field\n"
        "def f(path):\n"
        "    return redacted_log_field(path, 64, before='', checks=())\n"
    )
    references, findings = _census("messagefoundry/new.py", source)
    assert references == [_Reference("messagefoundry/new.py", "f", "redacted_log_field", True)]
    assert findings == []


def test_the_census_sees_a_reference_that_is_not_a_call() -> None:
    source = "from messagefoundry import logging_setup\nfield = logging_setup.redact_log_value\n"
    references, _ = _census("messagefoundry/new.py", source)
    assert references == [
        _Reference("messagefoundry/new.py", "<module>", "redact_log_value", False)
    ]


@pytest.mark.parametrize(
    "argument",
    [
        "before=request.path",
        "before=HEAD + request.path",
        "after=f' seen={seen}'",
        "before=_HEAD.upper()",
        "before=_DYNAMIC",
        "**context",
    ],
)
def test_the_census_refuses_context_that_is_not_constant(argument: str) -> None:
    source = (
        "from messagefoundry.logging_setup import redacted_log_field\n"
        "HEAD = 'a line: path='\n"
        "_HEAD = 'x'\n"
        "_DYNAMIC = HEAD + str(1)\n"
        "def f(request, seen, context):\n"
        f"    return redacted_log_field(request.text, 64, {argument}, checks=())\n"
    )
    _, findings = _census("messagefoundry/new.py", source)
    assert len(findings) == 1


@pytest.mark.parametrize(
    "argument", ["before=''", "before=HEAD", "before=HEAD + 'x'", "after=f'{HEAD} tail'"]
)
def test_the_census_accepts_literal_and_module_constant_context(argument: str) -> None:
    source = (
        "from messagefoundry.logging_setup import redacted_log_field\n"
        "_BASE = 'a line'\n"
        "HEAD = f'{_BASE}: path='\n"
        "def f(text):\n"
        f"    return redacted_log_field(text, 64, {argument}, checks=())\n"
    )
    _, findings = _census("messagefoundry/new.py", source)
    assert findings == []


_CALL = "    return redacted_log_field(text, 64, before=HEAD, checks=())\n"


@pytest.mark.parametrize(
    "shadow",
    [
        "def f(text, HEAD='x'):\n" + _CALL,
        "def f(text):\n    HEAD = text\n" + _CALL,
        "def f(text):\n    for HEAD in text:\n        pass\n" + _CALL,
        "def f(text):\n    if (HEAD := text):\n        pass\n" + _CALL,
        "HEAD, OTHER = 'x', 'y'\ndef f(text):\n" + _CALL,
        "HEAD += 'y'\ndef f(text):\n" + _CALL,
        "def g(text):\n    global HEAD\n    HEAD = text\ndef f(text):\n" + _CALL,
        "HEAD = 'z'\ndef f(text):\n" + _CALL,
    ],
    ids=["parameter", "local", "loop", "walrus", "tuple", "augmented", "global", "rebound"],
)
def test_the_census_refuses_a_constant_the_file_binds_again(shadow: str) -> None:
    """NEGATIVE CONTROL: before this rule each of these read ``HEAD`` as the module constant
    ``'x'``, so caller text could reach ``before`` past the census."""
    source = "from messagefoundry.logging_setup import redacted_log_field\nHEAD = 'x'\n" + shadow
    _, findings = _census("messagefoundry/new.py", source)
    assert len(findings) == 1


def test_the_census_still_accepts_a_constant_bound_once() -> None:
    """The control for the test above: the same file with no second binding is accepted."""
    source = (
        "from messagefoundry.logging_setup import redacted_log_field\nHEAD = 'x'\n"
        "def f(text):\n" + _CALL
    )
    _, findings = _census("messagefoundry/new.py", source)
    assert findings == []


def test_the_census_refuses_an_import_under_another_name() -> None:
    source = "from messagefoundry.logging_setup import redacted_log_field as field\n"
    _, findings = _census("messagefoundry/new.py", source)
    assert [finding.what for finding in findings] == ["redacted_log_field imported as field"]


# --- the code-level guard: a caller states its context -----------------------------------------


@pytest.mark.parametrize("missing", ["before", "checks"])
def test_redacted_log_field_has_no_default_for_before_or_checks(missing: str) -> None:
    """``before`` and ``checks`` are required keywords, so a caller cannot leave out the context
    that decides what its field hides. NEGATIVE CONTROL: on 33870a40944 both defaulted to empty and
    each call below returned a field."""
    given = {"before": "", "checks": ()}
    del given[missing]
    with pytest.raises(TypeError, match=missing):
        logging_setup.redacted_log_field("/a", 64, **given)  # type: ignore[arg-type]
