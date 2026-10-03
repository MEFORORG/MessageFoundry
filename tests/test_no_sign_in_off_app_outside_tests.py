# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""No shipped code builds the engine's API with sign-in off (ADR 0203; vault BACKLOG #2719).

The app factories take ``allow_no_auth=True`` for embedders and tests. An app built that way
resolves every route to the system identity, which holds every permission, and ``serve`` can never
reach that posture. ``harness/load/ingress_probe.py`` used to build one and serve it on loopback for
the life of the process, and the harness ships as a wheel, so that was an engine API with sign-in
off in shipped code. It now starts a signed-in ``serve`` subprocess, as every other rig does.

This walks the SOURCE of every Python file outside a ``tests`` directory and refuses the flag being
given any value but ``False``, in at least these spellings: a call keyword, a dict-literal key
(which covers ``**{...}`` and a ``State({...})``), an assignment to an attribute or a subscript
named for it (the flag the API reads is ``app.state.allow_no_auth``), ``setattr`` naming it, a
function parameter defaulting to it, and a local variable of that name. Two files are excepted,
each named below with its reason and its scope. It reads text, not a run: a value assembled at run
time (a computed name, a dict built elsewhere, an alias of ``setattr``) is outside its reach, so
read its zero as no more than that. A refusal inside the factories would cover every spelling, and
is an engine change this file does not make.
"""

from __future__ import annotations

import ast
import functools
import os
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]

_FLAG = "allow_no_auth"

#: Files where the flag may be set, each pinned to the exact number of lines that set it, so a
#: second site is refused and an exception that is no longer used fails too.
_EXEMPT: dict[str, tuple[int, str]] = {
    # The DAST sweep's open-auth canary: a deliberately injected authentication bypass, built so the
    # sweep can prove it detects one. Not shipped code.
    "scripts/security/dast_target.py": (1, "the DAST open-auth canary"),
}

#: Files where ONLY the factory pass-through is allowed: the value is the factory's own parameter,
#: a bare ``allow_no_auth`` name, handed on (``create_managed_app`` to ``create_app``, and
#: ``create_app`` to ``app.state``). A literal, any other expression, a parameter default other
#: than ``False`` and a local rebinding are all still refused there.
_PASS_THROUGH: dict[str, str] = {
    "messagefoundry/api/app.py": "the app factories hand their own parameter on",
}

#: Directory names the walk never enters: test suites (where the escape is legitimate), and
#: environments, caches and build output that are not this repository's source. Any directory
#: whose name starts with a dot is skipped too.
_SKIP_DIRS = frozenset({"tests", "node_modules", "__pycache__", "build", "dist", "venv", "env"})

#: Floors, well under the tree at landing (147 harness files, about 620 in all), so a walk gone
#: blind -- a moved root, a changed glob -- fails instead of reporting a clean zero.
_MIN_HARNESS_FILES = 100
_MIN_FILES = 400


@functools.cache
def _source_files() -> tuple[Path, ...]:
    found: list[Path] = []
    for root, dirs, files in os.walk(_REPO):
        # Pruned in place, so a virtual environment or node_modules is never listed at all.
        dirs[:] = sorted(
            d
            for d in dirs
            if d not in _SKIP_DIRS and not d.startswith(".") and not d.startswith("venv")
        )
        found += [Path(root) / name for name in sorted(files) if name.endswith(".py")]
    return tuple(found)


def _is_false(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _is_flag(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and node.value == _FLAG


def _names_flag(target: ast.expr) -> bool:
    """Whether an assignment target is, or holds, a name, attribute or subscript for the flag."""
    if isinstance(target, ast.Tuple | ast.List):
        return any(_names_flag(t) for t in target.elts)
    if isinstance(target, ast.Attribute):
        return target.attr == _FLAG
    if isinstance(target, ast.Subscript):
        return _is_flag(target.slice)
    return False


def _settings(node: ast.AST, *, pass_through: bool) -> list[ast.expr | None]:
    """The values ``node`` gives the flag, in each spelling the module docstring names.

    ``None`` stands for a value that is refused whatever it is (a local rebinding in a
    pass-through file)."""
    values: list[ast.expr | None] = []
    if isinstance(node, ast.Call):
        values += [k.value for k in node.keywords if k.arg == _FLAG]
        func = node.func
        name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
        if name == "setattr" and len(node.args) == 3 and _is_flag(node.args[1]):
            values.append(node.args[2])
    elif isinstance(node, ast.Dict):
        values += [v for k, v in zip(node.keys, node.values, strict=True) if _is_flag(k)]
    elif isinstance(node, ast.Assign | ast.AnnAssign | ast.AugAssign):
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if node.value is not None and any(_names_flag(t) for t in targets):
            values.append(node.value)
        if pass_through and any(isinstance(t, ast.Name) and t.id == _FLAG for t in targets):
            values.append(None)
    elif isinstance(node, ast.arguments):
        params = [*node.posonlyargs, *node.args]
        defaults = [None] * (len(params) - len(node.defaults)) + list(node.defaults)
        pairs = [
            *zip(params, defaults, strict=True),
            *zip(node.kwonlyargs, node.kw_defaults, strict=True),
        ]
        values += [d for arg, d in pairs if arg.arg == _FLAG and d is not None]
    return values


def _allowed(value: ast.expr | None, *, pass_through: bool) -> bool:
    if _is_false(value):
        return True
    return pass_through and isinstance(value, ast.Name) and value.id == _FLAG


def _offending_lines(source: str, *, pass_through: bool = False) -> list[int]:
    """Lines of ``source`` that give the flag anything it may not have here."""
    lines: list[int] = []
    for node in ast.walk(ast.parse(source)):
        for value in _settings(node, pass_through=pass_through):
            if not _allowed(value, pass_through=pass_through):
                where = value if value is not None else node
                lines.append(getattr(where, "lineno", 0))
    return sorted(lines)


def _rel(path: Path) -> str:
    return path.relative_to(_REPO).as_posix()


def test_no_code_outside_tests_builds_the_app_with_sign_in_off() -> None:
    files = _source_files()
    assert len(files) >= _MIN_FILES, f"CONTROL FAILED: the walk read only {len(files)} file(s)"
    harness_files = [f for f in files if _rel(f).startswith("harness/")]
    assert len(harness_files) >= _MIN_HARNESS_FILES, (
        f"CONTROL FAILED: the walk read only {len(harness_files)} harness file(s)"
    )
    offenders = [
        f"{rel}:{line}"
        for path in files
        if (rel := _rel(path)) not in _EXEMPT
        for line in _offending_lines(
            path.read_text(encoding="utf-8"), pass_through=rel in _PASS_THROUGH
        )
    ]
    assert not offenders, (
        f"these lines give {_FLAG} something other than False, which builds the engine API with "
        "sign-in off. Start a signed-in `serve` subprocess instead (harness/load/failover.py "
        f"EngineNode, harness/load/rigadmin.py): {offenders}"
    )


def test_each_exception_is_still_used_exactly_as_pinned() -> None:
    """An exception must not outlive its use, nor cover a second site added beside it."""
    assert len(_EXEMPT) >= 1 and len(_PASS_THROUGH) >= 1, "CONTROL FAILED: no exceptions read"
    for rel, (pinned, reason) in _EXEMPT.items():
        found = _offending_lines((_REPO / rel).read_text(encoding="utf-8"))
        assert len(found) == pinned, f"{rel} ({reason}): {pinned} site(s) pinned, found {found}"
    for rel, reason in _PASS_THROUGH.items():
        tree = ast.parse((_REPO / rel).read_text(encoding="utf-8"))
        handed_on = [
            v for n in ast.walk(tree) for v in _settings(n, pass_through=True) if v is not None
        ]
        assert handed_on, f"{rel} ({reason}) no longer hands {_FLAG} on; drop its exception"


def test_the_scan_finds_each_planted_shape() -> None:
    """CONTROL: the scan must be able to fail, on each shape it claims to see."""
    planted = (
        "app = create_managed_app(db_path=p, allow_no_auth=True)\n",
        "app = create_app(engine, allow_no_auth=flag)\n",
        'app = create_app(engine, **{"allow_no_auth": True})\n',
        'app.state = State({"allow_no_auth": True})\n',
        "app.state.allow_no_auth = True\n",
        "app.state.allow_no_auth: bool = True\n",
        "app.state.allow_no_auth, x = True, 1\n",
        'app.state._state["allow_no_auth"] = True\n',
        'setattr(app.state, "allow_no_auth", True)\n',
        'builtins.setattr(app.state, "allow_no_auth", True)\n',
        "def create_app(engine, allow_no_auth: bool = True): ...\n",
        "def create_app(engine, *, allow_no_auth: bool = True): ...\n",
    )
    for source in planted:
        assert _offending_lines("x = 1\n" + source) == [2], source
        # A pass-through file is held to the bare parameter, not let off.
        assert _offending_lines("x = 1\n" + source, pass_through=True) == [2], source
    # A local rebinding is refused in a pass-through file, whatever it is rebound to.
    assert _offending_lines("x = 1\nallow_no_auth = True\n", pass_through=True) == [2]
    # The walk itself reaches the file that used to hold the defect.
    assert any(_rel(f) == "harness/load/ingress_probe.py" for f in _source_files())


def test_the_scan_passes_what_is_not_a_sign_in_off_app() -> None:
    for source in (
        "app = create_managed_app(db_path=p, allow_no_auth=False)\n",
        "app = create_managed_app(db_path=p)\n",
        "app.state.allow_no_auth = False\n",
        "def create_app(engine, allow_no_auth: bool = False): ...\n",
        "def create_app(engine, *, allow_no_auth: bool = False): ...\n",
        'text = "allow_no_auth=True"\n',
    ):
        assert _offending_lines(source) == [], source
    for source in (
        "return create_app(engine, allow_no_auth=allow_no_auth)\n",
        "app.state.allow_no_auth = allow_no_auth\n",
    ):
        assert _offending_lines(source, pass_through=True) == [], source
        assert _offending_lines(source) == [1], source
