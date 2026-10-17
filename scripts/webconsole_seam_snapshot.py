# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Emit a STABLE, deterministic text snapshot of the engine-side seam contract the web console
(``messagefoundry-webconsole``, Option B / ADR 0065) depends on.

This is the enforced version-skew HANDSHAKE. The console is separately versioned and pins itself
against ``api._ui_seam.ENGINE_UI_SEAM``; a silent, incompatible change to the injected contract
(a renamed handler field, a re-signatured ``api.security`` dep, a DTO field the console renders that
was renamed) would break the console at RUNTIME within a supported seam -- mypy at the engine's
``deps = UiDeps(...)`` site catches builder-signature drift, but NOT a Pydantic DTO field rename
(that breaks render, not import). The engine test ``tests/test_webconsole_seam_snapshot.py``
regenerates this snapshot and diffs it against the golden ``tests/golden/webconsole_seam.snapshot``,
failing CI on an incompatible change the seam did not follow.

**The surface is DISCOVERED, not curated** (BACKLOG #1220). It used to be five hand-maintained
tuples, and three of them had drifted: 25 rendered DTOs were unlisted, ``api.security`` was missing
two symbols while carrying five stale ones, and an ``AuthService`` member the console calls was
absent. A hand-maintained list cannot detect its own omissions -- the gate's coverage IS the list, so
there is no outside vantage point from which a missing entry looks like anything. See
``scripts/seam_discovery.py`` for the walk and the fail-loud boundary.

The snapshot captures:
  1. ``ENGINE_UI_SEAM``, the value both sides pin against;
  2. the ``api._ui_seam`` dataclass field names (``UiDeps`` / ``CoreHandlers`` / ``AdminHandlers``)
     via ``dataclasses.fields`` -- the injected handler/reference bundle shape;
  3. the cross-seam surface the console consumes OUTSIDE the injected bundle, discovered from its own
     imports and uses: ``api.security`` deps, every other name it imports from ``auth.service``
     (BACKLOG #2015), ``AuthService`` members (methods AND properties), and the ``app.state``
     attributes it sets/reads;
  4. the DTO FIELD SETS the console renders, closed over nested models -- one level of field names
     was not enough, because a nested model's fields never appeared at all;
  5. the ENUM MEMBER sets and ``Literal`` VALUE sets those DTOs expose. Field names alone are not the
     contract: ``UploadedFileList.scope`` is a ``Literal`` the console renders as
     ``_SCOPE_NOTES[data.scope]``, so renaming a literal would KeyError at runtime while a
     field-name-only snapshot stayed byte-identical;
  6. what the console installs on the app, its route gates above all, read from a live mount
     (BACKLOG #2709; ``console_route_gates`` says what it covers and misses). This is the one
     section read from the imported console rather than from its source, so it imports this
     repository's console by path, whatever copy the process already holds (``repo_console``).

Usage:
  ``python scripts/webconsole_seam_snapshot.py``           print the snapshot
  ``python scripts/webconsole_seam_snapshot.py --digest``  print the derived seam value only
  ``python scripts/webconsole_seam_snapshot.py --write``   rewrite ENGINE_UI_SEAM AND the golden

Use ``--write``, never a shell redirect over the golden. A redirect writes the golden and never
``ENGINE_UI_SEAM``, in EVERY shell, and it fails GREEN rather than red: ``build_snapshot`` prints
whatever seam is imported, so a redirected golden AGREES with a stale or hand-typed constant and
``test_webconsole_seam_snapshot_matches_golden`` passes. Measured against a fabricated
``deadbeefdeadbeef``, only ``test_the_stored_seam_equals_the_derived_digest`` refused it.

The encoding damage is a SECOND hazard layered on that one, and it is shell-specific, so it must not
be read as the reason: Windows PowerShell 5.1's ``>`` emits UTF-16LE with a BOM, which the test
cannot decode as UTF-8 at all, while ``pwsh`` 7 and Git Bash write a clean file and still leave the
constant stale. An earlier version of this note gave only the encoding reason, which licensed the
redirect for anyone not on 5.1 -- the failure it was warning against.
"""

from __future__ import annotations

import ast
import contextlib
import dataclasses
import enum
import hashlib
import importlib.machinery
import importlib.util
import inspect
import re
import sys
import textwrap
import types
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

from pydantic import BaseModel

_REPO_ROOT = Path(__file__).resolve().parents[1]
_CONSOLE_DIR = _REPO_ROOT / "messagefoundry_webconsole"
_ENGINE_DIR = _REPO_ROOT / "messagefoundry"

# ANCHOR ON THE SCRIPT, NOT ON WHATEVER sys.path OFFERS (BACKLOG #1439). It is the same rule
# scripts/coord/alloc.ps1 states for `git` (BACKLOG #1060), and the same insert the siblings
# scripts/bench/stage_residency.py and scripts/tray/make_icons.py already carry. This file measures
# the engine/console contract of the repository it LIVES IN; without the insert it measured whichever
# engine the interpreter happened to find, and said nothing about the difference.
#
# Python puts the SCRIPT's directory on sys.path[0], never the current directory, so `scripts/` led
# the path and no entry offered `messagefoundry` until site-packages. In a worktree with no .venv of
# its own -- the normal state for these sessions -- the interpreter reached for is the primary
# checkout's, whose site-packages holds a path-based editable install (`_editable_impl_*.pth`
# containing the PRIMARY checkout's root). So `import messagefoundry` resolved to the PRIMARY tree
# while the discovery walk below read _CONSOLE_DIR and _ENGINE_DIR out of THIS one.
#
# The failure was silent and it pointed the wrong way. Measured 2026-09-03 in a worktree with no
# .venv of its own: `--write` printed the unchanged digest, rewrote both files with it, and
# reported success, while tests/test_webconsole_seam_snapshot.py (which runs under pytest,
# with the repo root already on sys.path) kept failing against a digest the script had never
# computed. The script's own success output is what misled -- a reader concludes the GATE is broken
# and starts "fixing" a gate that was right. This is the SDS-3.8 shape: an instrument answering a
# question adjacent to the one asked.
#
# Inserted at 0, so it wins over that .pth entry. tests/test_webconsole_seam_snapshot.py::
# test_the_script_run_by_path_computes_the_same_digest holds the property from outside, in a
# subprocess, because nothing INSIDE this process can observe which tree it failed to import.
sys.path.insert(0, str(_REPO_ROOT))

from messagefoundry.api import security  # noqa: E402
from messagefoundry.api._ui_seam import (  # noqa: E402
    ENGINE_UI_SEAM,
    AdminHandlers,
    CoreHandlers,
    UiDeps,
)
from messagefoundry.auth import service as auth_service  # noqa: E402
from messagefoundry.auth.permissions import Permission  # noqa: E402
from messagefoundry.auth.service import AuthService  # noqa: E402


def _load_discovery() -> Any:
    """Load the sibling discovery module by path.

    ``scripts/`` is not an importable package. Registering in ``sys.modules`` BEFORE
    ``exec_module`` is required, not cosmetic: ``@dataclass(slots=True)`` resolves its own module
    through ``sys.modules`` while the decorator runs, and an unregistered module makes that lookup
    return ``None`` and raise.
    """
    name = "_mf_seam_discovery"
    cached = sys.modules.get(name)
    if cached is not None:
        return cached
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parent / "seam_discovery.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_HEADER = (
    "# messagefoundry-webconsole ENGINE SEAM CONTRACT SNAPSHOT",
    "#",
    "# Deterministic serialization of the engine-side contract the web console depends on (ADR 0065).",
    "# Regenerate with: python scripts/webconsole_seam_snapshot.py --write",
    "# This is a GOLDEN gate: any diff means the seam contract changed - see the test's failure hint.",
    "# The surface below is DISCOVERED from the console's own imports and uses, never enumerated",
    "# by hand (BACKLOG #1220) - so a newly rendered DTO is covered with nobody editing a list.",
)


def _dataclass_fields(dc: type) -> list[str]:
    """Field names in declaration order (the injected bundle shape)."""
    return [f.name for f in dataclasses.fields(dc)]


def _dto_fields(dto: type) -> list[str]:
    """Sorted field names of a rendered DTO (Pydantic model or dataclass).

    ``model_computed_fields`` is unioned in because a computed field is rendered exactly like a
    declared one; omitting it would be the same class of blind spot as the curated tuples.
    """
    if isinstance(dto, type) and issubclass(dto, BaseModel):
        return sorted(set(dto.model_fields) | set(dto.model_computed_fields))
    if dataclasses.is_dataclass(dto):
        return sorted(f.name for f in dataclasses.fields(dto))
    raise TypeError(f"unsupported DTO type for {dto!r}: not a Pydantic model or dataclass")


def _member(obj: Any) -> str:
    """Render a seam member.

    Properties are rendered rather than skipped. ``inspect.signature`` RAISES on a property, and that
    limitation is why the retired ``_AUTH_SERVICE_METHODS`` tuple held methods only -- the renderer's
    capability had silently defined what counted as the contract, while the console read
    ``auth.action_step_up_required`` and five other properties across the seam.
    """
    if isinstance(obj, property):
        if obj.fget is None:
            return "property (write-only)"
        return f"property -> {inspect.signature(obj.fget).return_annotation!r}"
    if callable(obj):
        return str(inspect.signature(obj))
    return f"attribute: {type(obj).__name__}"


def _auth_service_symbol(obj: Any) -> str:
    """Render a name the console imports from ``auth.service`` (BACKLOG #2015).

    Classes need their own rules, because :func:`_member` renders a class by its constructor
    signature. That RAISES on an exception class with no ``__init__`` of its own, such as
    ``NotifyEmailAlreadySet``, so an exception renders its ancestry instead. A result class renders
    its constructor signature, its field names and its public properties. The console reads the
    fields and properties, and it also builds ``Elevation()`` with no arguments, so a field losing
    its default or changing type must move the digest too. A class none of these rules covers
    RAISES, like every other idiom this gate cannot render exactly.

    A constant renders by its type, not its value. The console imports the value from the installed
    engine, so both sides agree on it; a digest that moved on a value change would move for a change
    that cannot break the pair. A value the console HARD-CODES instead of importing is outside this
    section: it is not an import, so discovery never sees it.
    """
    if obj is AuthService:
        # Its constructor is the engine's to call, never the console's. Its members have their own
        # section, so rendering the signature here would move the seam for nothing the console uses.
        return "class; its members are the AuthService section"
    if not isinstance(obj, type):
        return _member(obj)
    is_record = issubclass(obj, BaseModel) or dataclasses.is_dataclass(obj)
    if issubclass(obj, BaseException):
        # The whole ancestry, because the console's except clauses match on it.
        ancestry = " < ".join(c.__name__ for c in obj.__mro__[1:] if c is not object)
        rendered = f"exception ({ancestry})"
        return f"{rendered}; fields: {', '.join(_dto_fields(obj))}" if is_record else rendered
    if issubclass(obj, enum.Enum):
        return f"enum: {', '.join(sorted(m.name for m in obj))}"
    if not is_record:
        raise TypeError(
            f"auth.service.{obj.__name__}: a class that is not an exception, enum, dataclass or "
            "pydantic model cannot be rendered exactly; teach _auth_service_symbol its shape"
        )
    # BaseModel's own properties (model_extra, model_fields_set) are pydantic's, not the contract.
    inherited = set(dir(BaseModel)) if issubclass(obj, BaseModel) else set()
    props = sorted(
        n
        for n in dir(obj)
        if not n.startswith("_")
        and n not in inherited
        and isinstance(inspect.getattr_static(obj, n), property)
    )
    # The constructor signature carries each parameter's type, default and whether it is required;
    # the field list adds any field the constructor does not take (``init=False``).
    return "; ".join(
        (
            f"constructor {inspect.signature(obj)}",
            f"fields: {', '.join(_dto_fields(obj))}",
            f"properties: {', '.join(props) or 'none'}",
        )
    )


#: The console package this repository holds. The route-gate section imports the console, while the
#: other sections read ``_CONSOLE_DIR`` as source, so the import must resolve to this tree. It is a
#: separate constant on purpose: a test points ``_CONSOLE_DIR`` at a copy of the source, which the
#: import cannot follow.
_CONSOLE_PACKAGE_DIR = _REPO_ROOT / "messagefoundry_webconsole"
_CONSOLE_PACKAGE = "messagefoundry_webconsole"

#: This repository's console modules, kept while another tree's copy holds ``sys.modules``, so a
#: second call reuses them and a test can patch the copy the table reads.
_REPO_CONSOLE_MODULES: dict[str, types.ModuleType] = {}


def _console_entries() -> dict[str, types.ModuleType]:
    prefix = f"{_CONSOLE_PACKAGE}."
    return {
        name: module
        for name, module in sys.modules.items()
        if name == _CONSOLE_PACKAGE or name.startswith(prefix)
    }


def _package_dir(module: types.ModuleType) -> Path:
    return Path(module.__file__ or "").resolve().parent


@contextlib.contextmanager
def repo_console() -> Iterator[types.ModuleType]:
    """This repository's console package, imported from its source whatever ``sys.path`` offers.

    An installed console is a COPY. Hatchling copies a ``force-include`` tree into site-packages even
    for an editable install, and CI installs the console that way, so a process that imported the
    console before this script did holds that copy. Mounting it would describe a console other than
    the source the other sections read. So when ``sys.modules`` holds a console from another tree,
    this moves that copy aside for the duration, imports the console from this repository by path,
    and puts the copy back afterwards. The repository's modules are kept for the next call.

    It refuses, rather than falls back, when this repository has no console to import."""
    current = sys.modules.get(_CONSOLE_PACKAGE)
    want = _CONSOLE_PACKAGE_DIR.resolve()
    if current is not None and _package_dir(current) == want:
        yield current
        return
    displaced = _console_entries()
    for name in displaced:
        del sys.modules[name]
    kept = _REPO_CONSOLE_MODULES.get(_CONSOLE_PACKAGE)
    if kept is not None and _package_dir(kept) == want:
        sys.modules.update(_REPO_CONSOLE_MODULES)
    imported = False
    try:
        console = sys.modules.get(_CONSOLE_PACKAGE) or _import_repo_console()
        if _package_dir(console) != want:
            raise RuntimeError(
                f"the route-gate table imported the web console from {_package_dir(console)}, "
                f"not from {_CONSOLE_PACKAGE_DIR}, so it would describe a different console than "
                "the one the other sections read"
            )
        imported = True
        yield console
    finally:
        ours = _console_entries()
        if not displaced:
            # Nothing was moved aside, so this repository's console stays the process's console.
            # A failed import leaves nothing worth keeping.
            if not imported:
                for name in ours:
                    del sys.modules[name]
        else:
            if imported:
                _REPO_CONSOLE_MODULES.update(ours)
            for name in ours:
                del sys.modules[name]
            sys.modules.update(displaced)


def _import_repo_console() -> types.ModuleType:
    """Import the console package from ``_CONSOLE_PACKAGE_DIR`` alone, never from ``sys.path``.

    Its submodules then resolve through the package's own ``__path__``, which is this tree."""
    spec = importlib.machinery.PathFinder.find_spec(
        _CONSOLE_PACKAGE, [str(_CONSOLE_PACKAGE_DIR.parent)]
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(
            f"the route-gate table found no web console at {_CONSOLE_PACKAGE_DIR}, and it reads "
            "only this repository's console"
        )
    module = importlib.util.module_from_spec(spec)
    sys.modules[_CONSOLE_PACKAGE] = module
    spec.loader.exec_module(module)
    return module


def _stub(label: str, *, takes_arguments: bool) -> Callable[..., Any]:
    """A stand-in for one ``UiDeps`` member, named after it. Registering a route never calls one.

    One stub per member, so a row says WHICH engine dependency or handler a route reaches: dropping
    ``Depends(deps.get_gate)``, the dual-control approval gate, moves the digest. FastAPI reads a
    ``Depends`` target's signature when a route is registered, so those stubs take no parameters
    and add none to the route."""

    def refuse() -> None:
        raise AssertionError("the route-gate table registers routes; it never serves a request")

    def handler(*_args: Any, **_kwargs: Any) -> Any:
        refuse()

    def dependency() -> None:
        refuse()

    stub = handler if takes_arguments else dependency
    stub.__qualname__ = label
    return stub


def _normalized_source(fn: Any) -> str:
    """A function's own source with comments, docstrings and formatting normalized away.

    Through ``ast.unparse``, so a reworded comment or a rewrapped line does not move the seam, and
    source rather than bytecode, which changes with the Python version. A lambda's source is the
    physical line holding it, which may not parse alone; that falls back to the stripped text.

    Cached by code object: every route's gate built by one factory shares that factory's code, and
    a reloaded module gets new code objects, so the cache never serves an edited function."""
    cached = _NORMALIZED_SOURCE.get(fn.__code__)
    if cached is None:
        cached = _NORMALIZED_SOURCE[fn.__code__] = _normalize(fn)
    return cached


#: ``_normalized_source`` by code object.
_NORMALIZED_SOURCE: dict[types.CodeType, str] = {}


def _normalize(fn: Any) -> str:
    source = textwrap.dedent(inspect.getsource(fn))
    try:
        tree = ast.parse(source)
    except SyntaxError:
        lines = (line.strip() for line in source.splitlines())
        return "\n".join(line for line in lines if line and not line.startswith("#"))
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            node.body = body[1:] or [ast.Pass()]
    return ast.unparse(tree)


def _qualified(obj: Any) -> str:
    return f"{obj.__module__}:{obj.__qualname__}"


def _console_helpers(fn: Any, found: dict[str, Any]) -> None:
    """Collect, transitively, every console function ``fn`` calls by its global name.

    A gate makes its decision partly in helpers such as ``_ui_action_step_up_ok``, which it names
    rather than captures, so the gate's own source does not carry them. Only functions defined in
    the console package are followed: an engine function is the engine's to version."""
    names = set(fn.__code__.co_names)
    for const in fn.__code__.co_consts:
        if inspect.iscode(const):
            names |= set(const.co_names)
    for name in sorted(names):
        value = fn.__globals__.get(name)
        if not inspect.isfunction(value):
            continue
        if value.__module__.partition(".")[0] != "messagefoundry_webconsole":
            continue
        key = _qualified(value)
        if key not in found:
            found[key] = value
            _console_helpers(value, found)


def _render_value(owner: str, var: str, value: Any, known: dict[int, str], seen: set[int]) -> str:
    """Render one captured value or default. A shape this table cannot render exactly RAISES."""
    from fastapi import params

    if id(value) in known:
        return known[id(value)]
    if isinstance(value, tuple) and all(isinstance(p, Permission) for p in value):
        return f"[{', '.join(p.value for p in value)}]"
    if value is None or isinstance(value, (bool, int, str)):
        return repr(value)
    if isinstance(value, enum.Enum):
        return f"{type(value).__name__}.{value.name}"
    if isinstance(value, params.Depends) and value.dependency is not None:
        return f"Depends({_render_callable(value.dependency, known, seen)})"
    if inspect.isfunction(value):
        return _render_callable(value, known, seen)
    raise TypeError(
        f"{owner}: {var} is a {type(value).__name__}, which the route-gate table cannot render "
        "exactly; teach _render_value its shape"
    )


def _render_callable(fn: Any, known: dict[int, str], seen: set[int] | None = None) -> str:
    """Render a gate, or any function a gate or route captured, so a weaker one moves the digest.

    A function renders as its qualified name, a digest of its own normalized source and of every
    console helper it calls by name, its defaults, and every value its closure captured. So turning
    a switch such as ``allow_mfa_pending`` on, replacing a captured hook, or editing the helper that
    decides a step-up moves the digest without renaming anything. A captured function, gate or not,
    renders the same way in place, and one already being rendered renders as a back-reference. A
    ``UiDeps`` member, or a stub standing in for one, renders as its name. Anything that is not a
    plain function, such as a bound method whose instance holds settings, RAISES, like every other
    shape this gate cannot render exactly.
    """
    if id(fn) in known:
        return known[id(fn)]
    if not inspect.isfunction(fn):
        raise TypeError(f"{fn!r} is not a plain function, so the route-gate table cannot read it")
    name = _qualified(fn)
    seen = set() if seen is None else seen
    if id(fn) in seen:
        return f"<back-reference {name}>"
    seen = seen | {id(fn)}
    parts: list[str] = []
    for var, cell in sorted(zip(fn.__code__.co_freevars, fn.__closure__ or (), strict=True)):
        parts.append(f"{var}={_render_value(name, var, cell.cell_contents, known, seen)}")
    for index, default in enumerate(fn.__defaults__ or ()):
        parts.append(f"default {index}={_render_value(name, 'a default', default, known, seen)}")
    for var, default in sorted((fn.__kwdefaults__ or {}).items()):
        parts.append(f"default {var}={_render_value(name, var, default, known, seen)}")
    helpers: dict[str, Any] = {}
    _console_helpers(fn, helpers)
    digest = hashlib.sha256(_normalized_source(fn).encode("utf-8"))
    for key in sorted(helpers):
        digest.update(f"\n{key}\n{_normalized_source(helpers[key])}".encode())
    gate = "gate " if security.is_route_gate(fn) else ""
    return f"{gate}{name}#{digest.hexdigest()[:12]}({'; '.join(parts)})"


def _render_route(route: Any, known: dict[int, str]) -> str:
    """Every top-level dependency a route runs, gates and others, in order, and what its
    declaration says when none of them is a gate.

    Top-level only, because that is all the engine's route check reads (``api.security``)."""
    calls = [d.call for d in route.dependant.dependencies]
    rendered = " + ".join(_render_callable(c, known) for c in calls)
    if any(security.is_route_gate(c) for c in calls):
        return rendered
    declared = security.route_declaration_of(route.endpoint)
    if declared is None:
        kind = "no gate, undeclared"
    else:
        kind = "no gate, public" if declared.public else "no gate, authorizes in body"
    return f"{kind}: {rendered}" if rendered else kind


def console_route_gates() -> list[tuple[str, str]]:
    """What the console installs on the app, gates first: one row per route, in registration order,
    then each mount, middleware and ``app.state`` hook (BACKLOG #2709; why is the #2709 entry in
    ``messagefoundry/api/_ui_seam.py``).

    The table is read from a live mount of the console onto a bare app, with stub handlers. The
    stub ``engine_seam`` is the console's own pin, which only lets ``mount_ui`` run; the table does
    not include it. Every ``bool`` field of ``UiDeps`` is on, so a route that a switch registers,
    such as the OIDC routes, is in the table too.

    It covers at least these, and misses at least these. Covered: each route's path, method and
    order; each top-level dependency's name, normalized source, defaults and captured values,
    recursively through captured functions, and the source of every console helper it calls by
    name; each mount's application class; each middleware class with its arguments; each
    ``app.state`` slot named for an authorizer, rendered the same way, and the type of every other
    hook. Missed: an engine helper a gate calls, which the engine versions; a route's endpoint body,
    such as a proof it spends there or an argument it passes to a handler; the inside and options of
    a mounted application; the inside of a middleware class; the value of a hook that is not an
    authorizer, such as the CSP; a route registered only when a ``UiDeps`` field that is not a
    ``bool`` is set, or when a ``bool`` one is off.
    """
    with repo_console() as console:
        return _route_gate_rows(console)


def _route_gate_rows(console: types.ModuleType) -> list[tuple[str, str]]:
    from fastapi import FastAPI
    from fastapi.routing import APIRoute, APIWebSocketRoute
    from starlette.routing import Mount

    known: dict[int, str] = {}

    def stub(name: str, *, takes_arguments: bool) -> Any:
        fn = _stub(name, takes_arguments=takes_arguments)
        known[id(fn)] = name
        return fn

    def handlers(cls: type, prefix: str) -> Any:
        fields = dataclasses.fields(cls)
        bundle = cls(**{f.name: stub(f"{prefix}.{f.name}", takes_arguments=True) for f in fields})
        known[id(bundle)] = prefix
        return bundle

    switches: dict[str, Any] = {
        f.name: True for f in dataclasses.fields(UiDeps) if f.type in ("bool", bool)
    }
    deps = UiDeps(
        engine_seam=min(console.SUPPORTED_ENGINE_SEAMS),
        default_scan_limit=0,
        core=handlers(CoreHandlers, "deps.core"),
        admin=handlers(AdminHandlers, "deps.admin"),
        **{
            name: stub(f"deps.{name}", takes_arguments=False)
            for name in ("get_engine", "get_gate", "cookie_secure")
        },
        **switches,
    )
    known[id(deps)] = "deps"
    app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)
    console.mount_ui(app, deps)
    # A low-priority route group is not in app.routes, so this walk would not see it; refuse it,
    # as scripts/security/route_gates.py does.
    if getattr(app.router, "_low_priority_routes", None):
        raise TypeError(
            "the console registered a low-priority route group, which this table cannot read"
        )

    rows: list[tuple[str, str]] = []
    for route in app.routes:
        if isinstance(route, APIWebSocketRoute):
            rows.append((f"WS {route.path}", _render_route(route, known)))
        elif isinstance(route, APIRoute):
            methods = ",".join(sorted((route.methods or set()) - {"HEAD", "OPTIONS"}))
            rows.append((f"{methods} {route.path}", _render_route(route, known)))
        elif isinstance(route, Mount):
            if getattr(route.app, "routes", None):
                raise TypeError(f"the console mounted an application with routes at {route.path}")
            rows.append((f"MOUNT {route.path}", f"mount {_qualified(type(route.app))}"))
        else:
            raise TypeError(
                f"the console registered a {type(route).__name__} at "
                f"{getattr(route, 'path', '?')}, which the route-gate table cannot read"
            )
    for index, middleware in enumerate(app.user_middleware):
        where = f"middleware {_qualified(middleware.cls)}"
        arguments = [_render_value(where, "an argument", a, known, set()) for a in middleware.args]
        arguments += [
            f"{k}={_render_value(where, k, v, known, set())}"
            for k, v in sorted(middleware.kwargs.items())
        ]
        rows.append(
            (f"middleware {index}", f"{_qualified(middleware.cls)}({', '.join(arguments)})")
        )
    for name, value in sorted(app.state._state.items()):
        # An authorizer is a gate the engine runs on its own route (/ws/stats runs the console's
        # cookie authorizer from ui_ws_authorize), so it renders in full. It is told by the SLOT the
        # engine reads, not by the function's own name, which a rename would change. Any other
        # hook, such as the CSP or a fragment renderer, is the console's own presentation and
        # renders as its type, so a change to it stays a package-only release.
        authorizer = "authorize" in name
        rendered = _render_callable(value, known) if authorizer else type(value).__name__
        rows.append((f"app.state.{name}", rendered))
    return rows


def contract_sections() -> list[tuple[str, list[tuple[str, str]]]]:
    """``(section title, [(key, value)])`` for the CONTRACT surface.

    **This function never reads ``ENGINE_UI_SEAM``.** That is what keeps the derived seam out of its
    own digest input, and it is an exclusion BY CONSTRUCTION rather than by filtering -- there is no
    "strip the seam line" step that could quietly stop matching. A reader checks the property by
    confirming the name does not appear in this function, not by trusting a regex.

    Keys are section-qualified and sorted within their section, because discovered names arrive in
    AST and filesystem order and that is the one place a derived value could move without the
    contract changing. The console route-gate section is the exception: it keeps registration
    order, which decides which of two matching routes serves a request, and which a live mount
    reproduces exactly.
    """
    discovery = _load_discovery()
    surface = discovery.discover(_CONSOLE_DIR, _ENGINE_DIR)
    dto_classes = discovery.discover_dto_classes(_CONSOLE_DIR)
    by_name = {f"{d.__module__}.{d.__qualname__}": d for d in dto_classes}

    sections: list[tuple[str, list[tuple[str, str]]]] = []

    for name, dc in (
        ("UiDeps", UiDeps),
        ("CoreHandlers", CoreHandlers),
        ("AdminHandlers", AdminHandlers),
    ):
        # Declaration order, NOT sorted: the injected bundle's field order is part of its shape.
        sections.append(
            (
                f"dataclass messagefoundry.api._ui_seam.{name}",
                [(f, "") for f in _dataclass_fields(dc)],
            )
        )

    sections.append(
        (
            "api.security surface (imported directly by the console, outside UiDeps)",
            [(s, _member(getattr(security, s))) for s in surface.security_symbols],
        )
    )
    sections.append(
        (
            "auth.service names imported by the console",
            [
                (s, _auth_service_symbol(getattr(auth_service, s)))
                for s in surface.auth_service_symbols
            ],
        )
    )
    sections.append(
        (
            "AuthService members reached by the console",
            [(m, _member(getattr(AuthService, m))) for m in surface.auth_service_methods],
        )
    )
    sections.append(
        (
            "app.state attributes the console sets/reads",
            [(a, "") for a in surface.app_state_attrs],
        )
    )
    sections.append(
        (
            "DTO fields rendered by the console (closed over nested models)",
            [(q, ", ".join(_dto_fields(by_name[q]))) for q in surface.dtos],
        )
    )
    sections.append(
        (
            "enum members reachable from those DTOs",
            [(n, ", ".join(v)) for n, v in sorted(discovery.enums_in_surface(dto_classes).items())],
        )
    )
    sections.append(
        (
            "Literal value sets on those DTOs",
            [
                (n, ", ".join(v))
                for n, v in sorted(discovery.literals_in_surface(dto_classes).items())
            ],
        )
    )
    sections.append(
        (
            "console route gates (each route's top-level gate dependencies, BACKLOG #2709)",
            console_route_gates(),
        )
    )
    return sections


def contract_digest() -> str:
    """The seam value: a 16-hex-character SHA-256 of the discovered contract surface.

    NOT a security control -- it is a change detector, so what is needed is accidental-collision
    avoidance across the distinct contract surfaces this project will ever produce, not preimage
    resistance. Anyone able to craft a colliding surface already has commit access to ``_ui_seam.py``,
    where writing the constant directly is strictly easier.

    64 bits, by the birthday bound ``N^2 / 2^(b+1)``: at N = 10,000 distinct surfaces (about 500x the
    ~20 seam moves to date) the collision probability is 2.7e-12. 32 bits would be 1 in 86, which is
    why this is not truncated further. SHA-256 rather than a non-approved digest because the engine
    renders a ``fips_mode`` attestation and a non-approved hash in the shipped surface invites a FIPS
    question for no benefit.
    """
    payload = "\n".join(
        f"{title}\t{key}\t{value}"
        for title, records in contract_sections()
        for key, value in records
    )
    return hashlib.sha256((payload + "\n").encode("utf-8")).hexdigest()[:16]


def build_snapshot() -> str:
    """Assemble the full deterministic snapshot text (newline-terminated)."""
    lines: list[str] = list(_HEADER)
    lines += ["", "## ENGINE_UI_SEAM", str(ENGINE_UI_SEAM)]
    for title, records in contract_sections():
        lines += ["", f"## {title}"]
        lines += [f"{key}: {value}" if value else key for key, value in records]
    return "\n".join(lines) + "\n"


_SEAM_FILE = _REPO_ROOT / "messagefoundry" / "api" / "_ui_seam.py"
_GOLDEN_FILE = _REPO_ROOT / "tests" / "golden" / "webconsole_seam.snapshot"
_SEAM_LINE = re.compile(r'^ENGINE_UI_SEAM: str = "[0-9a-f]{16}"$', re.MULTILINE)


def write_seam_and_golden() -> str:
    """Rewrite the constant and the golden to the current derived digest. Returns the digest.

    Deliberately does NOT touch ``messagefoundry_webconsole.SUPPORTED_ENGINE_SEAMS``. That constant
    is the independent half of a two-wheel handshake, and a tool that writes both sides turns the
    handshake into a self-consistent tautology -- it would remove the one place a human states "this
    console build is compatible with this engine contract". The failure message spells out the
    one-line edit instead.

    Refuses rather than guesses if the constant line does not match EXACTLY once: a source-rewriting
    tool that guesses is worse than one that stops.
    """
    source = _SEAM_FILE.read_text(encoding="utf-8")
    matches = _SEAM_LINE.findall(source)
    if len(matches) != 1:
        raise SystemExit(
            f"refusing to rewrite {_SEAM_FILE}: expected exactly one line matching "
            f"{_SEAM_LINE.pattern!r}, found {len(matches)}"
        )

    digest = contract_digest()
    _SEAM_FILE.write_text(
        _SEAM_LINE.sub(f'ENGINE_UI_SEAM: str = "{digest}"', source), encoding="utf-8", newline="\n"
    )

    # Rebuild with the NEW value in scope. The digest itself does not depend on the seam (see
    # contract_sections), but the snapshot's first section prints it.
    globals()["ENGINE_UI_SEAM"] = digest
    # Written explicitly rather than via a shell redirect, which would write this file and never the
    # constant rewritten above it. See the module docstring for why that fails green.
    _GOLDEN_FILE.write_text(build_snapshot(), encoding="utf-8", newline="\n")
    return digest


if __name__ == "__main__":
    if "--digest" in sys.argv:
        print(contract_digest())
    elif "--write" in sys.argv:
        value = write_seam_and_golden()
        print(f"ENGINE_UI_SEAM = {value}")
        print(f"  rewrote {_SEAM_FILE.relative_to(_REPO_ROOT).as_posix()}")
        print(f"  rewrote {_GOLDEN_FILE.relative_to(_REPO_ROOT).as_posix()}")
        print("  NOW SET THE CONSOLE SIDE BY HAND, in the same commit:")
        print("    messagefoundry_webconsole/__init__.py")
        print(f'      SUPPORTED_ENGINE_SEAMS: frozenset[str] = frozenset({{"{value}"}})')
    else:
        print(build_snapshot(), end="")
