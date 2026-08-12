# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""DISCOVER the engine-side seam surface the web console actually depends on (BACKLOG #1220).

``scripts/webconsole_seam_snapshot.py`` used to carry five hand-maintained tuples naming that
surface. A hand-maintained list cannot detect its own omissions -- **the gate's coverage IS the
list**, so there is no outside vantage point from which a missing entry looks like anything. Measured
against ``ebf4882a``, three of the five had drifted: 25 ``api.models`` classes the console renders
were unlisted, ``api.security`` was missing two symbols while carrying five it no longer imports, and
``AuthService.has_action_step_up`` was called by the console and absent. The proof it matters is in
the history: commit ``40a4d5d9`` added a REQUIRED field to ``UploadedFileList``, which the console
renders unconditionally, and moved no seam file at all.

This module derives the same surface by reading the console's own imports and uses, so a new
console-rendered DTO is covered with nobody editing anything.

**It runs in the generator and the test, never in the engine package.** ``messagefoundry/`` must not
import ``messagefoundry_webconsole`` (the one-way dependency rule, CLAUDE.md section 4) and must not
import ``scripts/``. Which DTOs the console renders is console-side knowledge, so discovery cannot
live behind the seam constant it feeds.

**Unresolvable idioms FAIL LOUD** (:class:`SeamDiscoveryError`) rather than being skipped. A silent
skip would recreate the enumeration blind spot inside the walk's control flow, which is strictly
worse than the tuple it replaces: a 30-line tuple was at least reviewable. A digest that LOOKS like
it covers content while quietly missing some is more convincing, and therefore more dangerous, than
an obviously hand-maintained list -- that is the whole finding behind #1220. Every loud case measures
zero occurrences today, so the guard costs nothing now and its first firing is a genuine new idiom.
"""

from __future__ import annotations

import ast
import dataclasses
import enum
import typing
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

from pydantic import BaseModel

MODELS_MODULE = "messagefoundry.api.models"
AUTH_MODELS_MODULE = "messagefoundry.api.auth_models"
SECURITY_MODULE = "messagefoundry.api.security"
AUTH_SERVICE_MODULE = "messagefoundry.auth.service"
AUTH_SERVICE_CLASS = "AuthService"

_DTO_MODULES = (MODELS_MODULE, AUTH_MODELS_MODULE)


class SeamDiscoveryError(RuntimeError):
    """An import/use idiom the walk cannot resolve exactly.

    Raised rather than skipped: see the module docstring. The message names file, line and source.
    """


def _fail(path: Path, node: ast.AST, what: str) -> typing.NoReturn:
    line = getattr(node, "lineno", 0)
    try:
        src = ast.unparse(node)
    except Exception:  # pragma: no cover - unparse is total for parsed trees
        src = "<unrenderable>"
    raise SeamDiscoveryError(f"{path}:{line}: {what}\n    {src}")


@dataclass(frozen=True, slots=True)
class DiscoveredSurface:
    """The seam surface, discovered. Every tuple is SORTED -- the digest downstream must not move
    because a filesystem walk or an AST visit changed order."""

    #: ``module.QualName`` for every DTO reachable from the console's imports. One list rather than a
    #: per-module split, because the closure crosses module boundaries by design and a DTO's
    #: DEFINING module is the only non-arbitrary key for it.
    dtos: tuple[str, ...]
    security_symbols: tuple[str, ...]
    auth_service_methods: tuple[str, ...]
    app_state_attrs: tuple[str, ...]


def _iter_modules(root: Path) -> Iterator[tuple[Path, ast.Module]]:
    """Every ``.py`` under ``root``, parsed. ``__pycache__`` is skipped -- a stale ``.pyc`` is not
    source, and globbing it in would make discovery depend on build residue."""
    for path in sorted(root.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        yield path, ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


# --- DTO seeds ---------------------------------------------------------------------------------


def _module_aliases(tree: ast.Module, module_name: str) -> set[str]:
    """Local names bound to ``module_name`` itself (``import x.y as m`` / ``from x import y as m``)."""
    aliases: set[str] = set()
    parent, _, leaf = module_name.rpartition(".")
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == module_name:
                    aliases.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module == parent:
            for alias in node.names:
                if alias.name == leaf:
                    aliases.add(alias.asname or alias.name)
    return aliases


def _seeds_from_tree(
    path: Path, tree: ast.Module, module_name: str, resolve: ModuleType
) -> set[str]:
    """DTO names this file seeds from ``module_name``.

    Handles the four idioms that can name a DTO exactly, and refuses the ones that cannot.
    """
    seeds: set[str] = set()

    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        for alias in node.names:
            if alias.name == "*" and node.module in _DTO_MODULES:
                _fail(path, node, "star import from a DTO module cannot be enumerated")
        if node.module == module_name:
            # Plain or aliased from-import. Seed the ORIGINAL name; the alias is a local label and
            # is irrelevant to what the engine ships.
            seeds.update(a.name for a in node.names)
        elif node.module and node.module.startswith("messagefoundry."):
            # A RE-EXPORT: some other messagefoundry module hands out a class that is really defined
            # on the DTO module. api/__init__ exposes models lazily (CLAUDE.md section 10), so this
            # is a reachable idiom even though it measures zero today.
            for alias in node.names:
                obj = getattr(resolve, alias.name, None)
                if _is_dto(obj) and getattr(obj, "__module__", None) == module_name:
                    seeds.add(alias.name)

    # Module-qualified access: bind the alias, then take every <alias>.<Name> attribute LOAD.
    aliases = _module_aliases(tree, module_name)
    if aliases:
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id in aliases
                and isinstance(node.ctx, ast.Load)
                and _is_dto(getattr(resolve, node.attr, None))
            ):
                seeds.add(node.attr)
            elif isinstance(node, ast.Call):
                fn = node.func
                if isinstance(fn, ast.Name) and fn.id == "getattr" and node.args:
                    base = node.args[0]
                    if isinstance(base, ast.Name) and base.id in aliases:
                        key = node.args[1] if len(node.args) >= 2 else None
                        if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
                            _fail(path, node, "dynamic getattr on a DTO module cannot be resolved")
                        seeds.add(key.value)
            elif isinstance(node, ast.Name) and node.id in aliases:
                # The alias escaping into a non-attribute position means names could be reached
                # indirectly, so the walk can no longer claim to have enumerated them. A literal
                # getattr is exact and is handled above, so it is the one other legal position.
                parent = _parent_of(tree, node)
                anchored = isinstance(parent, ast.Attribute) and parent.value is node
                caller = parent.func if isinstance(parent, ast.Call) else None
                resolved_getattr = isinstance(caller, ast.Name) and caller.id == "getattr"
                if not (anchored or resolved_getattr):
                    _fail(path, node, "DTO module alias used outside attribute access")

    return seeds


#: Parent links, per parsed tree. ``ast`` does not record them, and the alias-escape check needs to
#: ask whether a Name is the base of an Attribute. Keyed by ``id(tree)``; a tree is alive for the
#: duration of one ``discover()`` call, which is the cache's whole lifetime.
_PARENT_CACHE: dict[int, dict[int, ast.AST]] = {}


def _parent_of(tree: ast.Module, node: ast.AST) -> ast.AST | None:
    cache = _PARENT_CACHE.get(id(tree))
    if cache is None:
        cache = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                cache[id(child)] = parent
        _PARENT_CACHE[id(tree)] = cache
    return cache.get(id(node))


def _is_dto(obj: object) -> bool:
    return (isinstance(obj, type) and issubclass(obj, BaseModel)) or (
        dataclasses.is_dataclass(obj) and isinstance(obj, type)
    )


def _field_annotations(dto: type) -> list[object]:
    if isinstance(dto, type) and issubclass(dto, BaseModel):
        try:
            fields = dto.model_fields
        except Exception as exc:  # unresolved forward ref / pending model_rebuild
            raise SeamDiscoveryError(
                f"{dto.__module__}.{dto.__name__}: model fields are unresolvable ({exc}); "
                "the closure cannot be completed, so the surface would be under-covered"
            ) from exc
        return [f.annotation for f in fields.values()]
    # Reached only for a dataclass DTO -- _is_dto() gates every caller, and mypy cannot carry that
    # narrowing across the call boundary.
    return [f.type for f in dataclasses.fields(typing.cast("Any", dto))]


def _closure(seeds: set[str], module: ModuleType, path_hint: str) -> set[type]:
    """Every DTO reachable from ``seeds`` through field annotations, to fixpoint.

    Nesting matters because the snapshot records field NAMES one level deep with no recursion, so a
    nested model's field set is otherwise absent entirely. Measured: 50 seeds reach 74 classes.

    The walk deliberately does NOT stop at a module boundary. A rendered DTO that exposes a model
    defined elsewhere still ships that model's field set across the seam, so filtering the closure to
    the seed module would drop it -- recreating the enumeration blind spot one level down, which is
    the specific failure this module exists to remove. Classes are returned rather than bare names so
    the caller can key them by their DEFINING module and two same-named DTOs cannot collide.
    """
    found: dict[str, type] = {}
    queue: list[type] = []

    for name in sorted(seeds):
        obj = getattr(module, name, None)
        if obj is None:
            raise SeamDiscoveryError(
                f"{path_hint}: {name!r} is imported from {module.__name__} but is not defined there"
            )
        if _is_dto(obj):
            queue.append(typing.cast(type, obj))
        # Enums, type aliases and plain functions ride in on the same import statement; they are not
        # DTOs and carry no field set. Their VALUES are captured separately by the generator.

    while queue:
        dto = queue.pop()
        key = f"{dto.__module__}.{dto.__qualname__}"
        if key in found:
            continue
        found[key] = dto
        for annotation in _field_annotations(dto):
            for nested in _models_in(annotation):
                if f"{nested.__module__}.{nested.__qualname__}" not in found:
                    queue.append(nested)
    return set(found.values())


def qualified(dtos: set[type]) -> tuple[str, ...]:
    """Sorted ``module.QualName`` for a discovered DTO set."""
    return tuple(sorted(f"{d.__module__}.{d.__qualname__}" for d in dtos))


def _models_in(annotation: object) -> list[type]:
    """Every pydantic/dataclass DTO appearing anywhere in a (possibly generic) annotation."""
    out: list[type] = []
    stack = [annotation]
    while stack:
        cur = stack.pop()
        if _is_dto(cur):
            out.append(typing.cast(type, cur))
            continue
        stack.extend(typing.get_args(cur))
    return out


def enums_in_surface(dtos: set[type]) -> dict[str, tuple[str, ...]]:
    """Enum classes reachable from the surface, with their MEMBER names.

    Recorded because the console renders enum members; a member rename breaks render exactly the way
    a field rename does, and field-name-only recording cannot see it.
    """
    out: dict[str, tuple[str, ...]] = {}
    for dto in dtos:
        for annotation in _field_annotations(dto):
            for found in _enums_in(annotation):
                out[f"{found.__module__}.{found.__qualname__}"] = tuple(
                    sorted(m.name for m in found)
                )
    return out


def _enums_in(annotation: object) -> list[type[enum.Enum]]:
    out: list[type[enum.Enum]] = []
    stack = [annotation]
    while stack:
        cur = stack.pop()
        if isinstance(cur, type) and issubclass(cur, enum.Enum):
            out.append(cur)
            continue
        stack.extend(typing.get_args(cur))
    return out


def literals_in_surface(dtos: set[type]) -> dict[str, tuple[str, ...]]:
    """``Literal[...]`` VALUE sets per field.

    ``UploadedFileList.scope`` is ``Literal["own", "any_owner"]`` and the console renders it as
    ``_SCOPE_NOTES[data.scope]``. Renaming a literal would KeyError at runtime while a field-NAME
    snapshot stayed byte-identical -- the same failure class the gate exists to catch, on the very
    field whose addition already slipped through.
    """
    out: dict[str, tuple[str, ...]] = {}
    for dto in dtos:
        if not (isinstance(dto, type) and issubclass(dto, BaseModel)):
            continue
        for field_name, field in dto.model_fields.items():
            values = _literal_values(field.annotation)
            if values:
                out[f"{dto.__module__}.{dto.__qualname__}.{field_name}"] = values
    return out


def _literal_values(annotation: object) -> tuple[str, ...]:
    found: list[str] = []
    stack = [annotation]
    while stack:
        cur = stack.pop()
        if typing.get_origin(cur) is typing.Literal:
            found.extend(str(a) for a in typing.get_args(cur))
            continue
        stack.extend(typing.get_args(cur))
    return tuple(sorted(found))


# --- api.security, AuthService, app.state ------------------------------------------------------


def _security_symbols(trees: list[tuple[Path, ast.Module]]) -> set[str]:
    found: set[str] = set()
    for path, tree in trees:
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == SECURITY_MODULE:
                for alias in node.names:
                    if alias.name == "*":
                        _fail(path, node, "star import from api.security cannot be enumerated")
                    found.add(alias.name)
    return found


def _auth_service_receivers(tree: ast.Module) -> set[str]:
    """Local names that hold an ``AuthService``.

    Annotation-driven rather than name-driven. A bare name intersection (every attribute name in the
    console, intersected with AuthService's public methods) over-covers by about 11 because those
    names collide with ``AdminHandlers`` fields, which would move the seam for methods the console
    never calls -- and a gate that moves for unrelated reasons is one people stop reading.
    """
    receivers: set[str] = set()

    def _names_an_auth_service(annotation: ast.expr | None) -> bool:
        if annotation is None:
            return False
        for sub in ast.walk(annotation):
            if isinstance(sub, ast.Name) and sub.id == AUTH_SERVICE_CLASS:
                return True
            if (
                isinstance(sub, ast.Constant)
                and isinstance(sub.value, str)
                and AUTH_SERVICE_CLASS in sub.value
            ):
                return True
        return False

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            args = node.args
            for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs):
                if _names_an_auth_service(arg.annotation):
                    receivers.add(arg.arg)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if _names_an_auth_service(node.annotation):
                receivers.add(node.target.id)
        elif isinstance(node, ast.Assign):
            # `auth = get_auth(request)` -- the sanctioned way the console obtains the service.
            value = node.value
            fn = value.func if isinstance(value, ast.Call) else None
            named = (
                fn.id
                if isinstance(fn, ast.Name)
                else (fn.attr if isinstance(fn, ast.Attribute) else None)
            )
            if named == "get_auth":
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        receivers.add(target.id)
    return receivers


def _auth_service_methods(trees: list[tuple[Path, ast.Module]], auth_service: type) -> set[str]:
    public = {n for n in dir(auth_service) if not n.startswith("_")}
    found: set[str] = set()
    for _path, tree in trees:
        receivers = _auth_service_receivers(tree)
        if not receivers:
            continue
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id in receivers
                and node.attr in public
            ):
                found.add(node.attr)
    return found


def _state_attr(node: ast.Attribute) -> str | None:
    """``<expr>.state.X`` -> ``X``."""
    inner = node.value
    if isinstance(inner, ast.Attribute) and inner.attr == "state":
        return node.attr
    return None


def _app_state_attrs(
    console: list[tuple[Path, ast.Module]], engine: list[tuple[Path, ast.Module]]
) -> set[str]:
    """Two-sided: console reads intersected with engine writes, plus console writes.

    The intersection is what makes this exact without a name heuristic. The console reads
    ``exposure_protected`` / ``loopback`` / ``public_origin`` off a parameter annotated
    ``app_state: object``, which has no syntactic anchor at all -- but they ARE string literals in
    ``getattr`` calls, and the engine assigns them, so the intersection recovers them while dropping
    unrelated getattr literals.
    """
    engine_writes: set[str] = set()
    for _path, tree in engine:
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store):
                attr = _state_attr(node)
                if attr:
                    engine_writes.add(attr)

    console_reads: set[str] = set()
    console_writes: set[str] = set()
    for _path, tree in console:
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                attr = _state_attr(node)
                if attr:
                    (console_writes if isinstance(node.ctx, ast.Store) else console_reads).add(attr)
            elif isinstance(node, ast.Call):
                fn = node.func
                if isinstance(fn, ast.Name) and fn.id == "getattr" and len(node.args) >= 2:
                    key = node.args[1]
                    if isinstance(key, ast.Constant) and isinstance(key.value, str):
                        console_reads.add(key.value)
    return (console_reads & engine_writes) | console_writes


# --- the public entry point --------------------------------------------------------------------


def discover(console_dir: Path, engine_dir: Path) -> DiscoveredSurface:
    """The seam surface, read off the console's own imports and uses."""
    import importlib

    models = importlib.import_module(MODELS_MODULE)
    auth_models = importlib.import_module(AUTH_MODELS_MODULE)
    auth_service = getattr(importlib.import_module(AUTH_SERVICE_MODULE), AUTH_SERVICE_CLASS)

    console = list(_iter_modules(console_dir))
    engine = list(_iter_modules(engine_dir))

    model_seeds: set[str] = set()
    auth_seeds: set[str] = set()
    for path, tree in console:
        model_seeds |= _seeds_from_tree(path, tree, MODELS_MODULE, models)
        auth_seeds |= _seeds_from_tree(path, tree, AUTH_MODELS_MODULE, auth_models)

    dtos = _closure(model_seeds, models, str(console_dir)) | _closure(
        auth_seeds, auth_models, str(console_dir)
    )

    return DiscoveredSurface(
        dtos=qualified(dtos),
        security_symbols=tuple(sorted(_security_symbols(console))),
        auth_service_methods=tuple(sorted(_auth_service_methods(console, auth_service))),
        app_state_attrs=tuple(sorted(_app_state_attrs(console, engine))),
    )


def discover_dto_classes(console_dir: Path) -> set[type]:
    """The DTO classes behind :attr:`DiscoveredSurface.dtos`, for callers that need the objects
    (field sets, enum members, literal values) rather than their names."""
    import importlib

    models = importlib.import_module(MODELS_MODULE)
    auth_models = importlib.import_module(AUTH_MODELS_MODULE)

    model_seeds: set[str] = set()
    auth_seeds: set[str] = set()
    for path, tree in _iter_modules(console_dir):
        model_seeds |= _seeds_from_tree(path, tree, MODELS_MODULE, models)
        auth_seeds |= _seeds_from_tree(path, tree, AUTH_MODELS_MODULE, auth_models)
    return _closure(model_seeds, models, str(console_dir)) | _closure(
        auth_seeds, auth_models, str(console_dir)
    )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Discover the webconsole seam surface.")
    _repo = Path(__file__).resolve().parents[1]
    parser.add_argument("--console", type=Path, default=_repo / "messagefoundry_webconsole")
    parser.add_argument("--engine", type=Path, default=_repo / "messagefoundry")
    ns = parser.parse_args()

    surface = discover(ns.console, ns.engine)
    for section, values in dataclasses.asdict(surface).items():
        print(f"## {section} ({len(values)})")
        for value in values:
            print(f"  {value}")
