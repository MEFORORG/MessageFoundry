# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The connection configuration schema, derived from the engine by introspection (ADR 0007).

The VS Code connection editor used to enumerate transports and their settings by hand in
TypeScript. That copy could only ever be a stale mirror of :mod:`messagefoundry.config.wiring`: it
covered 9 of 11 transports and offered per-transport hints for 6, against the ~180 keyword-only
parameters the factories actually accept, and nothing failed when the engine grew a setting -- the
field simply never appeared in the GUI. This module makes the engine the single source of truth and
lets the editor render whatever the installed engine supports.

Deliberately introspection-only: it takes **no config directory** and never calls ``load_config``.
A schema fetch describes the ENGINE, not a workspace, so it cannot fail because some unrelated
module in the user's config dir does not import, and it never trips the Windows config-source trust
check (ADR 0036). That also keeps it fast enough to call on every editor open.

Help text and per-direction applicability come from the trailing comments on each factory
parameter, which is where the authors already write them. Attribution is span-based
(``ast`` + ``tokenize``): a parameter's declaration can span several physical lines, and the comment
usually sits on the LAST of them --

    tls_key_password: str
    | EnvRef
    | None = None,  # passphrase for an ENCRYPTED tls_key_file (put the secret in env())

so a first-physical-line scrape drops precisely the multi-line (and therefore most security-
relevant) ones."""

from __future__ import annotations

import ast
import inspect
import re
import tokenize
import typing
from collections import abc
from io import StringIO
from typing import Any

from .connections_file import _INBOUND_KEYS, _OUTBOUND_KEYS, _TRANSPORTS
from .wiring import EnvRef, _is_secret_setting

#: Bump when the emitted shape changes in a way a consumer must notice. The IDE refuses a schema
#: whose major version it does not understand rather than rendering a form it cannot round-trip.
SCHEMA_VERSION = 1

#: A leading ``inbound:`` / ``outbound:`` / ``OUTBOUND:`` marker on a parameter's comment declares
#: the direction it applies to. Unmarked parameters apply to both.
_DIRECTION_MARKER = re.compile(r"^\s*(inbound|outbound)\s*:\s*", re.IGNORECASE)

#: Comment prose that marks a parameter as required for a direction, e.g. MLLP's
#: ``# OUTBOUND: the downstream peer (required; may be env()).``
_REQUIRED_HINT = re.compile(r"\brequired\b", re.IGNORECASE)


def build_schema() -> dict[str, Any]:
    """The full connection schema: every transport, every setting, plus the direction key sets."""
    transports: dict[str, Any] = {}
    for name, factory in sorted(_TRANSPORTS.items()):
        transports[name] = _describe_transport(factory)
    return {
        "schemaVersion": SCHEMA_VERSION,
        "transports": transports,
        "directionKeys": {
            "inbound": sorted(_INBOUND_KEYS),
            "outbound": sorted(_OUTBOUND_KEYS),
        },
    }


def _describe_transport(factory: Any) -> dict[str, Any]:
    comments, sections = _param_comments(factory)
    params: dict[str, Any] = {}
    # eval_str resolves the annotations to real objects: wiring.py uses `from __future__ import
    # annotations`, so without it every annotation is the STRING "str | EnvRef | None" and each
    # setting would report type "unknown" and env False.
    try:
        signature = inspect.signature(factory, eval_str=True)
    except (NameError, TypeError):  # pragma: no cover - unresolvable annotation; degrade to strings
        signature = inspect.signature(factory)
    for name, param in signature.parameters.items():
        if param.kind is not inspect.Parameter.KEYWORD_ONLY:
            continue  # the factories are keyword-only; anything else is not an authorable setting
        described = _describe_param(name, param, comments.get(name, ""))
        if name in sections:
            described["section"] = sections[name]
        params[name] = described
    return {"params": params, "doc": _summary(factory)}


def _describe_param(name: str, param: inspect.Parameter, comment: str) -> dict[str, Any]:
    annotation = param.annotation
    direction, help_text = _split_direction(comment)
    default = param.default if param.default is not inspect.Parameter.empty else None
    return {
        "type": _type_name(annotation),
        "choices": _choices(annotation),
        "default": _jsonable_default(default),
        # No default at all => the factory raises without it. A parameter defaulting to None may
        # still be mandatory in one direction (MLLP `host`), which the comment declares; that is
        # reported per-direction below rather than as a single flag.
        "required": param.default is inspect.Parameter.empty,
        "requiredHint": bool(_REQUIRED_HINT.search(help_text)),
        "env": _accepts_env(annotation),
        # A GUI must render this read-only: connections.toml cannot express it (see _code_first_only).
        "codeFirstOnly": _code_first_only(annotation),
        "secret": _is_secret_setting(name),
        "direction": direction,
        "help": help_text,
    }


def _split_direction(comment: str) -> tuple[str | None, str]:
    """Split a leading ``inbound:``/``outbound:`` marker off the help text."""
    match = _DIRECTION_MARKER.match(comment)
    if match is None:
        return None, comment.strip()
    return match.group(1).lower(), comment[match.end() :].strip()


#: Container origins that authoring writes as a TOML table or array. ``collections.abc`` forms count:
#: SOAP's ``body_secrets`` is annotated ``Mapping[str, EnvRef]``, and matching only ``dict``/``list``
#: reported it as "unknown", which cost a GUI its table control and let a text box stringify the map.
_TABLE_ORIGINS = (dict, list, tuple, set, abc.Mapping, abc.MutableMapping, abc.Sequence, abc.Set)


def _type_name(annotation: Any) -> str:
    """A coarse type tag the form can pick a control from: bool -> checkbox, int -> number, ..."""
    if annotation is inspect.Parameter.empty:
        return "unknown"
    members = _literal_values_typed(_union_members(annotation))
    for candidate, tag in ((bool, "bool"), (int, "int"), (float, "float"), (str, "str")):
        if candidate in members:
            return tag
    if any(_origin_of(member) in _TABLE_ORIGINS for member in members):
        return "table"
    # An env()-ONLY setting (``EnvRef | None``, e.g. File's credential_password) carries no scalar
    # member at all. What the author types is an environment KEY, which is a string.
    if EnvRef in members:
        return "str"
    return "unknown"


def _literal_values_typed(members: tuple[Any, ...]) -> tuple[Any, ...]:
    """``members`` with each ``Literal[...]`` replaced by the TYPES of its allowed values.

    A choice-valued setting is annotated ``Literal["move", "delete", "leave"]`` (optionally ``| None``)
    and so carries **no bare ``str`` member**: the scalar scan in :func:`_type_name` would report it
    "unknown" and the form would lose the control it picks from ``type`` for precisely the settings it
    can render as a dropdown. A literal's values carry the setting's real type, so use theirs."""
    out: list[Any] = []
    for member in members:
        if typing.get_origin(member) is typing.Literal:
            out.extend(type(value) for value in typing.get_args(member))
        else:
            out.append(member)
    return tuple(out)


def _code_first_only(annotation: Any) -> bool:
    """Can this setting NOT be expressed in connections.toml, so a GUI must not offer to edit it?

    True when the annotation is a CONTAINER whose element type is :class:`EnvRef`. ``parse_env_setting``
    desugars ``{env = "KEY"}`` only at the TOP level and does not descend, so a nested table's values
    arrive as raw dicts and the factory rejects them -- SOAP's ``body_secrets`` documents exactly that
    ("deliberately no TOML/GUI round-trip"). Offering an editable control would invite the author to
    write something the engine refuses at load."""
    for member in _union_members(annotation):
        if _origin_of(member) in _TABLE_ORIGINS and EnvRef in typing.get_args(member):
            return True
    return False


def _choices(annotation: Any) -> list[Any] | None:
    """The allowed values of a ``Literal[...]`` annotation, else None (a free-text control)."""
    for member in _union_members(annotation):
        if typing.get_origin(member) is typing.Literal:
            return list(typing.get_args(member))
    return None


def _accepts_env(annotation: Any) -> bool:
    """May this setting be written as ``{env = "KEY"}``? True when EnvRef is in the annotation."""
    return EnvRef in _union_members(annotation)


def _union_members(annotation: Any) -> tuple[Any, ...]:
    if annotation is inspect.Parameter.empty:
        return ()
    args = typing.get_args(annotation)
    return args if args and _is_union(annotation) else (annotation,)


def _is_union(annotation: Any) -> bool:
    import types

    origin = typing.get_origin(annotation)
    return origin is typing.Union or origin is types.UnionType


def _origin_of(member: Any) -> Any:
    return typing.get_origin(member) or member


def _jsonable_default(value: Any) -> Any:
    """Defaults must survive JSON. An exotic default is reported as null rather than crashing."""
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, tuple)):
        return [_jsonable_default(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _jsonable_default(item) for key, item in value.items()}
    return None


def _summary(factory: Any) -> str:
    """The factory docstring's first sentence -- the transport's one-line description."""
    doc = inspect.getdoc(factory) or ""
    return " ".join(doc.split("\n\n")[0].split()) if doc else ""


def _param_comments(factory: Any) -> tuple[dict[str, str], dict[str, str]]:
    """``(help_by_param, section_by_param)`` read from the factory's parameter comments.

    Two comment shapes appear in these signatures and they mean different things:

    * a TRAILING comment (same physical line as code) documents that parameter. A declaration may
      span several lines and the comment normally sits on the last of them, so the span --
      ``arg.lineno`` through the end of its annotation/default -- is what claims it. A first-line
      scrape would miss every multi-line parameter, which is most of the TLS block.
    * an OWN-LINE comment is either a group heading for the parameters that follow
      (``# Inbound DoS guards (...):``) or a continuation of the parameter above when it opens with
      a direction marker (MLLP's ``host`` is documented across two lines that way). Headings become
      ``section`` metadata for grouping in the UI; continuations are appended to the help above."""
    try:
        source = inspect.getsource(factory)
    except (OSError, TypeError):  # pragma: no cover - a C or dynamically built factory
        return {}, {}
    try:
        tree = ast.parse(source)
    except SyntaxError:  # pragma: no cover - defensive
        return {}, {}
    func = next((node for node in tree.body if isinstance(node, ast.FunctionDef)), None)
    if func is None:  # pragma: no cover - defensive
        return {}, {}

    trailing: dict[int, str] = {}  # line -> comment, for comments that follow code
    own_line: dict[int, str] = {}  # line -> comment, for comments alone on their line
    try:
        for token in tokenize.generate_tokens(StringIO(source).readline):
            if token.type != tokenize.COMMENT:
                continue
            text = token.string.lstrip("#").strip()
            code_before = source.splitlines()[token.start[0] - 1][: token.start[1]].strip()
            (trailing if code_before else own_line)[token.start[0]] = text
    except (tokenize.TokenError, IndexError):  # pragma: no cover - defensive
        return {}, {}

    help_by_param: dict[str, str] = {}
    section_by_param: dict[str, str] = {}
    previous_arg: str | None = None
    previous_end = func.lineno
    for arg, default in _kwonly_with_defaults(func):
        start, end = arg.lineno, _span_end(arg, default)
        parts = [text for line, text in sorted(trailing.items()) if start <= line <= end]
        if parts:
            help_by_param[arg.arg] = " ".join(parts)
        # Own-line comments sitting between the previous parameter and this one.
        between = [text for line, text in sorted(own_line.items()) if previous_end < line < start]
        headings: list[str] = []
        for text in between:
            if previous_arg is not None and _DIRECTION_MARKER.match(text):
                existing = help_by_param.get(previous_arg, "")
                help_by_param[previous_arg] = f"{existing} {text}".strip()
            else:
                headings.append(text.rstrip(":"))
        if headings:
            section_by_param[arg.arg] = " ".join(headings)
        previous_arg, previous_end = arg.arg, end
    return help_by_param, section_by_param


def _span_end(arg: ast.arg, default: ast.expr | None) -> int:
    """The last physical line of a parameter declaration (annotation and default included)."""
    candidates = [arg.end_lineno or arg.lineno]
    if arg.annotation is not None and arg.annotation.end_lineno:
        candidates.append(arg.annotation.end_lineno)
    if default is not None and default.end_lineno:
        candidates.append(default.end_lineno)
    return max(candidates)


def _kwonly_with_defaults(func: ast.FunctionDef) -> list[tuple[ast.arg, ast.expr | None]]:
    defaults: list[ast.expr | None] = list(func.args.kw_defaults)
    while len(defaults) < len(func.args.kwonlyargs):  # pragma: no cover - ast keeps these aligned
        defaults.insert(0, None)
    return list(zip(func.args.kwonlyargs, defaults, strict=True))
