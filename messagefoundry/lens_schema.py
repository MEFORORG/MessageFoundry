# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Derive the Steps-view parameter INPUT schema from the transform vocabulary's own type hints.

The analyst-facing half of ADR 0076 §5 (editable params): the Steps editor renders one input widget
per editable call argument. Rather than hand-maintain a per-op input table IDE-side (a second source
of truth that drifts from the signatures), the engine emits the widget schema **derived from the
action + diagnostic signatures** — the same "the engine owns the grammar so it lives beside the
vocabulary; the IDE consumes the JSON contract only" split :mod:`messagefoundry.lens` already follows.

The schema is a sibling of :mod:`messagefoundry.hl7schema` — a stdout JSON-schema emitter, shelled by
the IDE as ``messagefoundry lens schema --json``. It adds **no runtime dependency** (ADR 0076 §6.5
forbids one in phases 1-2): stdlib :mod:`inspect` + :mod:`typing` only.

Two sources are covered, so no row kind bypasses the schema-driven renderer:

* :mod:`messagefoundry.actions` — the transform verbs (``copy_field`` … ``delete_segment``).
* :mod:`messagefoundry.diagnostics` — ``log_note`` / ``checkpoint`` (the diagnostic rows).

JSON contract (the IDE consumes this; prefer "at least these fields" over an exhaustive claim,
CLAUDE.md §11): a mapping ``op-name -> [param, ...]`` where each ``param`` carries **at least**::

    {"name": str, "kind": str, "required": bool, "keyword_only": bool}

and optionally ``"choices": [str, ...]`` (``enum`` kinds only), ``"nullable": true`` (an
``X | None`` slot), and ``"default": <JSON scalar>`` (present only when the parameter's default is a
JSON scalar — a non-serializable sentinel like ``code_lookup``'s ``_UNSET`` is omitted so
:func:`json.dumps` never raises). ``kind`` is one of ``str`` / ``int`` / ``float`` / ``bool`` /
``enum`` / ``list`` / ``codeset`` / ``unknown`` — a minimal, stable vocabulary the IDE maps to a
widget (``enum`` -> dropdown, ``int`` / ``float`` -> number field, everything else -> text).
"""

from __future__ import annotations

import inspect
from collections.abc import Mapping, Sequence
from types import UnionType
from typing import Any, Literal, Union, get_args, get_origin

from messagefoundry import actions, diagnostics

__all__ = ["op_param_schema"]


def _kind_and_choices(annotation: Any) -> tuple[str, list[str] | None, bool]:
    """Map a resolved type annotation to a ``(kind, choices, nullable)`` triple.

    ``choices`` is populated only for a ``Literal[...]`` (``enum``); ``nullable`` is set when the
    annotation is ``X | None`` / ``Optional[X]`` (the kind is then the inner ``X``'s). Anything the
    minimal vocabulary does not recognize maps to ``"unknown"`` (the IDE renders it as a text input),
    so an unrecognized hint never breaks the schema."""
    origin = get_origin(annotation)
    if origin is Union or origin is UnionType:  # X | None (PEP 604) or Optional[X]
        members = get_args(annotation)
        non_none = [m for m in members if m is not type(None)]
        nullable = len(non_none) != len(members)
        if len(non_none) == 1:  # the common `int | None` / `str | None` — unwrap to the inner kind
            kind, choices, inner_nullable = _kind_and_choices(non_none[0])
            return kind, choices, nullable or inner_nullable
        return "unknown", None, nullable  # a genuine multi-member union has no single widget
    if origin is Literal:
        return "enum", [str(arg) for arg in get_args(annotation)], False
    if annotation is str:
        return "str", None, False
    if (
        annotation is bool
    ):  # before int — bool is an int subclass, but annotations compare by identity
        return "bool", None, False
    if annotation is int:
        return "int", None, False
    if annotation is float:
        return "float", None, False
    if origin is Sequence or origin is list or origin is tuple:
        return "list", None, False
    if origin is Mapping or origin is dict:
        # A mapping argument is a captured code-set name (``code_lookup``'s ``table``) — the IDE's
        # code-set hint. It is an expression slot (never a per-row literal), so this is advisory.
        return "codeset", None, False
    return "unknown", None, False


def _is_json_scalar(value: object) -> bool:
    """Whether ``value`` is a JSON scalar (so it can be emitted as a parameter ``default``).

    Excludes the sentinels a vocabulary default can carry — ``code_lookup``'s ``_UNSET`` (a bare
    ``object``) and a mapping table — so :func:`json.dumps` of the whole schema never raises."""
    return value is None or isinstance(value, (str, int, float, bool))


def _param_entry(param: inspect.Parameter) -> dict[str, Any]:
    """One parameter's schema entry (see the module docstring for the field contract)."""
    kind, choices, nullable = _kind_and_choices(param.annotation)
    entry: dict[str, Any] = {
        "name": param.name,
        "kind": kind,
        # A parameter with no default is a required argument; one with a default is optional.
        "required": param.default is inspect.Parameter.empty,
        "keyword_only": param.kind is inspect.Parameter.KEYWORD_ONLY,
    }
    if choices is not None:
        entry["choices"] = choices
    if nullable:
        entry["nullable"] = True
    if param.default is not inspect.Parameter.empty and _is_json_scalar(param.default):
        entry["default"] = param.default
    return entry


def _params_for(func: Any) -> list[dict[str, Any]]:
    """The editable-parameter entries for one vocabulary function.

    ``eval_str=True`` is REQUIRED: both source modules carry ``from __future__ import annotations``,
    so raw annotations are strings — ``eval_str`` resolves them against each function's own module
    globals (where ``Message`` / ``Mapping`` / ``Sequence`` / ``Literal`` are imported). A leading
    ``msg`` parameter is dropped (it is the message the Handler threads through, never an editable
    input — matching ``lens._render_params``); ``*args`` / ``**kwargs`` are recognized-only, never
    editable, so they are skipped (e.g. ``log_note``'s ``*values``)."""
    params = list(inspect.signature(func, eval_str=True).parameters.values())
    entries: list[dict[str, Any]] = []
    for i, param in enumerate(params):
        if i == 0 and param.name == "msg":
            continue
        if param.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD):
            continue
        entries.append(_param_entry(param))
    return entries


def op_param_schema() -> dict[str, list[dict[str, Any]]]:
    """The transform-vocabulary parameter schema: ``op-name -> [param, ...]``.

    Derived from the ``__all__`` verbs of :mod:`messagefoundry.actions` and
    :mod:`messagefoundry.diagnostics` (see the module docstring for the per-parameter contract).
    Deterministic order: actions in ``actions.__all__`` order, then the diagnostics."""
    schema: dict[str, list[dict[str, Any]]] = {}
    for module in (actions, diagnostics):
        for name in module.__all__:
            schema[name] = _params_for(getattr(module, name))
    return schema
