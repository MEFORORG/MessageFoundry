# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Deterministic Corepoint action-list import → code-first ``@router``/``@handler`` modules (ADR 0086).

The **inverse** of the ADR 0076 §2 vocabulary table: where the lens *reads* a vocabulary-authored
Handler back into a typed action-list, this importer *writes* a Corepoint-style action-list forward
into a real ``.py`` config module that calls the same :mod:`messagefoundry.actions` vocabulary and
returns :class:`~messagefoundry.Send` against the :class:`~messagefoundry.parsing.message.Message`
API. The emitted ``.py`` is the **only** artifact and execution path — there is no interpreter and no
declarative model (CLAUDE.md §12 / ADR 0076).

**The input schema is VALIDATED** (BACKLOG #105; ADR 0086 §2's "synthetic-until-validated" caveat is
discharged by the 2026-07-24 amendment). A real Corepoint export is **XML, not JSON**:

* Root ``<Package>``; the transform logic lives in ``<Package>/<ActionList Name= Desc=>/<List>``.
* Inside a ``<List>`` the statement elements are ``<Block>``, ``<Line>``, ``<Call>``, ``<Case>``,
  ``<Foreach>``, ``<If>``, ``<Loop>``, ``<Try>``. ``<Block>``/``<Call>`` (and the control elements)
  carry a nested ``<List>``/``<Actions>``, so an action-list is a **recursive control-flow tree**, not
  a flat sequence.
* Attributes are ``@Data`` (the statement), optional ``@Disabled``, optional ``@Comment``; ``<If>`` and
  ``<Try>`` may carry **no** ``@Data`` (pure containers).
* **``@Data`` is wrapped in rich-text markup** (syntax-colouring tags + HTML entities) — it MUST be
  run through :func:`strip_markup` to recover the plain ``Verb operand operand …`` statement. This was
  the single biggest schema surprise: without the strip, the overwhelming majority of statements fail
  to classify because the leading token is markup, not a verb.
* **``<Block>`` is a comment / section label, not an action** — it is preserved as a comment in the
  generated module and never emitted as a step.
* Operands are ``$variable``, ``%tree/path`` (a message-tree path), ``"string literal"``,
  ``[bracketed option]`` and ``(parenthesised condition)``; the verb vocabulary is **42 verbs**, of
  which 30 cover 99.4% of statements.
* Other ``<Package>``-level subtrees (``<Connection>``/``<Table>``/``<Row>``/``<Cell>``, ``<Codeset>``,
  ``<Association>``, ``<Namespace>``, ``<FtpEndpoint>``, ``<SOAPWSEndpoint>``, ``<DataPoint>``,
  ``<OtherObjects>``) are **not** modelled — the parser never walks them, so they are neither imported
  nor a crash. Endpoint wiring therefore comes out as an inert, `deployed=False` placeholder to
  hand-finish. This tolerance is **package-level only**: an element inside an action-list is a
  *statement position*, so an unmodelled tag there is reported and counted, never skipped.

:func:`parse_package` is the primary, validated path; :func:`parse_any` sniffs (a leading ``<`` ⇒ XML)
and :func:`parse_export` remains for the **superseded synthetic JSON model** ADR 0086 §2(a) defined
before the real shape was known.

**Every source element inside an action-list is accounted for (count-and-log ethos).** A verb that
maps to a v1 vocabulary helper emits that call; an **unmapped** verb — and an element whose **tag** this
layer does not model — is *never silently dropped*: it emits an in-place ``# TODO: Corepoint …
hand-finish`` marker naming the intended target field when one is recoverable, its subtree is parsed
and inlined beneath it, and the import summary counts it. An unmapped verb emits **no live code at
all** — see :func:`_decline` for why the former ``msg.set`` "passthrough stub" was not inert.
Control flow is emitted as real nested Python (``if``/``for``/``while``/``try``) whose *condition* is
left as an explicit, dead (`False`) hand-finish placeholder — a Corepoint condition expression is not
Python and is never guessed. ``@Disabled`` is honoured at **every** level — a single statement, a
``<Block>``, a whole ``<ActionList>``, the ``<Package>`` — and always renders as commented-out
pseudo-source: never live code, and a disabled action-list is not routed to.

**Security (untrusted input).** A Corepoint export is untrusted *data*, never instructions
(CLAUDE.md §5/§8). Every value lifted from the export into generated Python source is rendered through
:func:`_lit` (:func:`json.dumps`), which emits a fully-escaped string/list/dict **literal** — a stray
quote, newline, or backslash cannot break out of the literal into executable code, so a hostile export
cannot inject code into the generated module. A value JSON *can* render but Python cannot read back —
``null``/``true``/``false``/a non-finite number, or a string carrying an unpaired surrogate — is
refused as a :class:`CorepointImportError` rather than written into a module that fails at import or at
encode. Text that rides into a *comment* is flattened by :func:`_comment_text` (whitespace collapsed,
non-whitespace controls deleted), so a crafted ``@Data``/``@Comment``, action class name, or recovered
target field cannot escape the ``#`` into a statement, and a NUL cannot make the module uncompilable.
XML is parsed through **defusedxml** with ``forbid_dtd``/``forbid_entities``/``forbid_external`` all
on, so a billion-laughs or external-entity payload raises instead of expanding.
Paths ride across as data to :meth:`Message.set` at run time.

**Message handles become Python locals (BACKLOG #313).** An action-list works on several message
trees at once; a Handler receives one ``msg``. The parse builds the step tree first, then
:class:`_Flow` walks it in statement order: the input handle is ``msg``, a whole-tree clone binds
``<local> = <source>.copy()``, a ``MsgCreate`` naming a message type and a version binds
``<local> = Message.parse(<skeleton>)``, and field writes and sends address the local of the handle
they name. Whatever the walk cannot settle raises at the send or ``MsgCreate`` site; nothing falls
back to sending ``msg``.

Pure (parse + string codegen): no network, no message content, no dependency beyond the engine's
vendored ``defusedxml`` copy (``messagefoundry/_vendor/defusedxml/``) and its own HL7 model
(:mod:`messagefoundry.parsing.message`, which builds a ``MsgCreate`` skeleton) — safe to run anywhere.
"""

from __future__ import annotations

import html
import json
import keyword
import re
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from math import isfinite
from pathlib import Path
from typing import TYPE_CHECKING, Any
from xml.etree.ElementTree import (  # nosec B405 — exception type only; every parse goes through defusedxml
    ParseError,
)

from messagefoundry._vendor.defusedxml.common import DefusedXmlException
from messagefoundry._vendor.defusedxml.ElementTree import fromstring as _xml_fromstring
from messagefoundry.connection_names import CONNECTION_NAME_MAX_LENGTH, is_connection_name
from messagefoundry.controlchars import strip_control_chars
from messagefoundry.parsing.message import Message

if TYPE_CHECKING:  # runtime never needs the class — only the annotations do
    from collections.abc import Callable, Iterator
    from xml.etree.ElementTree import (  # nosec B405 — type-only import (see above)
        Element,
    )

__all__ = [
    "CorepointImportError",
    "Action",
    "UnmappedAction",
    "Control",
    "Handler",
    "Destination",
    "Channel",
    "ChannelResult",
    "ImportResult",
    "RoleToken",
    "Operand",
    "strip_markup",
    "parse_roles",
    "tokenize_statement",
    "parse_package",
    "parse_any",
    "parse_export",
    "generate_module",
    "import_corepoint",
]


class CorepointImportError(ValueError):
    """The import could not be completed: the export is malformed, or the module it generates is not
    valid Python.

    A subclass of :class:`ValueError`; the CLI turns it into a clean error + non-zero exit. The
    importer treats the export as untrusted data, so a structural problem — including a rejected DTD
    or entity payload — is reported, never raised as an uncaught traceback.

    Most arms blame the EXPORT (malformed XML/JSON, a missing field). One does not: a
    :class:`SyntaxError` caught by :func:`_verify_compilable` is a defect in this generator, so an
    operator reading the message should not assume their export is at fault."""


# --- intermediate action model ----------------------------------------------


@dataclass(frozen=True)
class Action:
    """A mapped transform step — a v1 vocabulary call ready to emit.

    ``args`` are already-rendered Python source fragments for the positional arguments *after* the
    leading message argument; ``keywords`` are ``(name, rendered_value)`` pairs. ``source_class`` is
    the originating Corepoint action class (kept for provenance in comments/summaries).

    ``target`` is the Python local the call writes: ``msg`` for the input handle, or the local a
    clone or ``MsgCreate`` bound for another handle (BACKLOG #313, step 2). It is always a name this
    module generated, never export text."""

    source_class: str
    vocabulary: str
    args: tuple[str, ...]
    keywords: tuple[tuple[str, str], ...] = ()
    target: str = "msg"


@dataclass(frozen=True)
class UnmappedAction:
    """A source action with no v1 vocabulary mapping — emitted as a visible TODO marker, never code.

    ``detail`` is a short human note for the marker, and it is where the recovered target field rides
    when the export names one: there is deliberately NO field to carry a stub target, because there is
    no stub. See :func:`_decline` for why a "best-effort passthrough" line is not inert."""

    source_class: str
    detail: str


@dataclass(frozen=True)
class _Deferred:
    """What the handle flow needs to settle a statement once it knows what each handle holds there.

    Produced by the parse, read by :class:`_Flow`, never rendered. ``flat`` is the markup-free
    reading's finished step: such a statement has no handle roles to map against, so the flow only
    applies the statement's whole-tree writes and then emits ``flat`` unchanged."""

    verb: str
    operands: tuple[Operand, ...]
    qualified: bool = False
    in_control: bool = False
    flat: Action | UnmappedAction | None = None
    # Every handle the statement names as a whole tree, in EITHER reading of its markup, so a span
    # class the role layer does not list cannot hide a handle from the fail-closed write rule.
    named: frozenset[str] = frozenset()
    # Every word of the statement that is neither an operand nor the verb, styled or not (see
    # :func:`_statement_words`). Field writes, clones and ``MsgCreate`` are all judged on these.
    words: tuple[str, ...] = ()
    # Whether the verb was styled as a keyword span. Only a field write reads this (see _Flow), and
    # the default is the fail-closed one: an unstyled verb declines.
    styled: bool = False


@dataclass(frozen=True)
class Control:
    """A non-leaf element of the ``<Package>`` control-flow tree — a construct with a nested body.

    ``kind`` is the *emitted* shape, deliberately named after the Python it becomes so the generator
    stays a dumb renderer:

    ``"block"``   a ``<Block>`` section label / ``<Call>`` inline — a **comment** plus its body at the
                  *same* indentation (a ``<Block>`` is a label, never an action, so it emits no step).
    ``"call"``    an ``ActionListCall``. With its target list inlined it renders like ``"block"``, and
                  the list runs in its own handle scope (see :meth:`_Flow._call`). With nothing
                  inlined it renders a TODO marker and counts unmapped.
    ``"if"``      with ``branches`` of kind ``"elif"``/``"else"``.
    ``"for"``     ``ForEach`` · ``"while"`` ``Loop`` · ``"break"`` ``LoopExit``.
    ``"try"``     with ``branches`` of kind ``"except"`` (``Catch``).
    ``"case"``    ``ChooseFrom``/``<Case>`` with ``branches`` of kind ``"match"`` (``Matching``).
    ``"send"``    a ``MsgSend`` — ``args`` carries the rendered destination-name literal (empty when
                  the export names none, which degrades to a TODO marker rather than a guess).
                  ``message`` is the local it delivers. ``refusal`` is non-empty when the handle it
                  sends holds no message the import can identify at that point; the render then
                  raises at the send site instead of sending (BACKLOG #313).
    ``"clone"``   a whole-tree ``MsgTreeCopy`` that binds a handle to a local: ``args`` is
                  ``(local, "<source>.copy()")`` (BACKLOG #313).
    ``"create"``  a ``MsgCreate`` that binds a handle to a local: ``args`` is
                  ``(local, "Message.parse(<skeleton>)")``. One with too little to build a valid MSH
                  carries a ``refusal`` instead and renders as a raise (BACKLOG #313).
    ``"pending"`` the parse's placeholder for a statement whose rendering depends on what each
                  handle holds at that point. :class:`_Flow` replaces every one; none is rendered.
    ``"exit"``    ``Returns``/``ActionListExit``/``ActionListStop`` — no faithful vocabulary form, so a
                  TODO marker (never a silent flatten).
    ``"unknown"`` an element in a statement position whose TAG this layer does not model (a ``<Switch>``,
                  a ``<Lines>`` typo, a future construct) — a TODO marker whose body is inlined and
                  counted, because dropping the subtree is exactly the accept-and-drop this importer
                  refuses. The marker says the scope was lost, so a human re-scopes it.
    ``"disabled"`` an element carrying ``@Disabled`` — the whole subtree is preserved as commented-out
                  pseudo-source and is **never** emitted as live code. Also carries a whole
                  ``<ActionList>``/``<Package>`` switched off at the top (see :func:`_disabled_scope`).

    ``detail`` is the markup-stripped statement (the condition/operands) and rides only into comments.
    A Corepoint condition is not a Python expression, so a control's *condition* is emitted as an
    explicit dead placeholder (``if False:``/``for _item in []:``) beside a TODO — never guessed."""

    kind: str
    source_verb: str
    detail: str = ""
    args: tuple[str, ...] = ()
    body: tuple[Step, ...] = field(default_factory=tuple)
    branches: tuple[Control, ...] = field(default_factory=tuple)
    # RAW text (escaped at the render site, like ``detail``). Only ``"send"`` and ``"create"`` set it.
    refusal: str = ""
    # The local a ``"send"`` delivers. A name this module generated, never export text. Empty until
    # :class:`_Flow` binds it, and the render refuses an empty one, so no send can default to ``msg``.
    message: str = ""
    # What :class:`_Flow` reads to settle a ``"pending"``/``"send"``, and the writes of an ``"unknown"``.
    deferred: _Deferred | None = None


# One node of a handler body: a mapped vocabulary call, an unmapped TODO, or a control construct.
Step = Action | UnmappedAction | Control


@dataclass(frozen=True)
class Handler:
    """One Corepoint handler: an ordered tree of mapped/unmapped/control steps + its destinations.

    ``disabled`` marks a handler whose whole ``<ActionList>`` (or the ``<Package>`` around it) carried
    ``@Disabled``: its body is emitted as commented-out pseudo-source and the router does **not**
    forward to it, so an action-list switched off in Corepoint can never come back on through the
    import."""

    name: str
    steps: tuple[Step, ...]
    destinations: tuple[str, ...]
    disabled: bool = False


@dataclass(frozen=True)
class Destination:
    """An outbound endpoint: its connection name + the rendered connector-factory call source."""

    name: str
    connector: str  # "MLLP" | "File" — drives the import list
    call: str  # e.g. 'MLLP(host="10.0.0.9", port=6000)'


@dataclass(frozen=True)
class Channel:
    """A parsed Corepoint channel: one inbound, a router over N handlers, and the outbounds they use."""

    module_name: str  # file stem + inbound connection name, e.g. IB_DEMO_ADT
    inbound_connector: str  # "MLLP" | "File"
    inbound_call: str  # e.g. "MLLP(port=2600)"
    router_name: str
    destinations: tuple[Destination, ...]
    handlers: tuple[Handler, ...]
    # Which input layer produced this channel: "xml" (the validated ``<Package>`` export) or "json"
    # (the superseded synthetic model). Drives the generated module's provenance header and whether
    # the endpoints are emitted as inert ``deployed=False`` placeholders — the XML export carries no
    # modelled connection subtree, so its wiring is a hand-finish stub that binds nothing.
    source_format: str = "json"


# --- result model ------------------------------------------------------------


@dataclass(frozen=True)
class ChannelResult:
    """The codegen outcome for one channel: the module source + mapped/unmapped counts (count-and-log)."""

    module_name: str
    filename: str
    source: str
    mapped: int
    unmapped: int
    unmapped_classes: tuple[str, ...]
    # Set when this channel's module_name collided with an earlier one and was deterministically
    # suffixed (``IB_DUP`` → ``IB_DUP_2``); the original stem so the rename is surfaced, never silent.
    renamed_from: str | None = None
    # How many ``@Disabled`` elements were preserved as commented-out pseudo-source rather than emitted
    # as live code. Counted separately from mapped/unmapped so the summary never claims a disabled
    # element shipped, and never claims it vanished either (count-and-log).
    disabled: int = 0


@dataclass(frozen=True)
class ImportResult:
    """The whole-import summary across channels — the count-and-log record the CLI prints/emits."""

    channels: tuple[ChannelResult, ...]

    @property
    def total_mapped(self) -> int:
        return sum(c.mapped for c in self.channels)

    @property
    def total_unmapped(self) -> int:
        return sum(c.unmapped for c in self.channels)

    @property
    def total_disabled(self) -> int:
        return sum(c.disabled for c in self.channels)

    def to_json(self) -> dict[str, Any]:
        return {
            "channels": [
                {
                    "module": c.module_name,
                    "filename": c.filename,
                    "mapped": c.mapped,
                    "unmapped": c.unmapped,
                    "unmapped_classes": list(c.unmapped_classes),
                    "renamed_from": c.renamed_from,
                    "disabled": c.disabled,
                }
                for c in self.channels
            ],
            "total_mapped": self.total_mapped,
            "total_unmapped": self.total_unmapped,
            "total_disabled": self.total_disabled,
        }


# --- the mapping table (INVERSE of ADR 0076 §2) ------------------------------
#
# Each entry maps a Corepoint action class to a v1 vocabulary helper and the export keys that supply
# its positional/keyword arguments. Widening this roster is an ordinary addition (ADR 0086 §2 mirrors
# ADR 0076's "widening the roster is ordinary; widening the grammar needs an amendment").


def _map_action(raw: dict[str, Any]) -> Action | UnmappedAction:
    """Map one export action object to a mapped :class:`Action` or an :class:`UnmappedAction`.

    Reads the action ``class`` (the Corepoint action-class name) and dispatches on it. A recognized
    class with a missing required field is reported as :class:`CorepointImportError` (a malformed
    export), *not* silently coerced — an unrecognized class degrades to :class:`UnmappedAction`."""
    cls = _req_str(raw, "class", "action")

    if cls == "ItemCopy":
        return Action(
            cls,
            "copy_field",
            (_lit(_req_str(raw, "source", cls)), _lit(_req_str(raw, "destination", cls))),
        )
    if cls == "ItemReplace":
        return Action(
            cls,
            "set_field",
            (_lit(_req_str(raw, "target", cls)), _lit(_req_str(raw, "value", cls))),
        )
    if cls == "ItemAppend":
        return Action(
            cls,
            "append_to_field",
            (_lit(_req_str(raw, "target", cls)), _lit(_req_str(raw, "suffix", cls))),
        )
    if cls in ("ItemFormatDate", "ItemTransformDate"):
        kws: list[tuple[str, str]] = []
        in_fmt = raw.get("inputFormat")
        if isinstance(in_fmt, str):
            kws.append(("in_fmt", _lit(in_fmt)))
        return Action(
            cls,
            "format_date",
            (_lit(_req_str(raw, "target", cls)), _lit(_req_str(raw, "outputFormat", cls))),
            tuple(kws),
        )
    if cls in ("ItemConvert", "ItemFormat"):
        return Action(
            cls,
            "convert_case",
            (_lit(_req_str(raw, "target", cls)), _lit(_req_str(raw, "mode", cls))),
        )
    if cls == "ItemCodeLookup":
        table = raw.get("table")
        if not isinstance(table, dict):
            raise CorepointImportError(
                f"ItemCodeLookup action requires an object 'table', got {type(table).__name__}"
            )
        kws2: list[tuple[str, str]] = []
        if "default" in raw:
            kws2.append(("default", _lit(raw["default"])))
        return Action(
            cls, "code_lookup", (_lit(_req_str(raw, "target", cls)), _lit(table)), tuple(kws2)
        )
    if cls == "ItemSplit":
        dests = raw.get("destinations")
        if not isinstance(dests, list) or not all(isinstance(d, str) for d in dests):
            raise CorepointImportError(
                "ItemSplit action requires a 'destinations' array of field paths"
            )
        return Action(
            cls,
            "split_field",
            (
                _lit(_req_str(raw, "source", cls)),
                _lit(_req_str(raw, "separator", cls)),
                _lit(dests),
            ),
        )
    if cls in ("SegmentCopy", "ItemSegmentCopy"):
        kws3: list[tuple[str, str]] = []
        occ = raw.get("occurrence")
        if isinstance(occ, int) and not isinstance(occ, bool):
            kws3.append(("occurrence", str(occ)))
        return Action(cls, "copy_segment", (_lit(_req_str(raw, "segment", cls)),), tuple(kws3))
    if cls in ("SegmentDelete", "ItemSegmentDelete"):
        return Action(cls, "delete_segment", (_lit(_req_str(raw, "segment", cls)),))

    # Unrecognized: never dropped. The recovered target rides into the marker TEXT, not into a live
    # ``msg.set`` line — see :func:`_decline` for why that stub was never the inert marker it claimed.
    # Both ``cls`` and the target stay RAW here, and that is deliberate: unlike every other value this
    # layer handles neither has been through a grammar, so both need escaping — but a comment needs a
    # different escape from a literal, and the renderer is the one place that knows a value is about
    # to become a comment. :func:`_generate_steps` applies :func:`_comment_text`; escaping here too
    # would leave a reader unable to tell which of the two is the contract.
    recovered = raw.get("target") or raw.get("destination") or raw.get("source")
    detail = f"no v1 vocabulary mapping for Corepoint {cls}"
    if isinstance(recovered, str) and recovered:
        detail += f"; intended target {recovered}"
    return UnmappedAction(cls, detail)


# --- export parsing (defensive; untrusted data) ------------------------------


def parse_export(text: str) -> tuple[Channel, ...]:
    """Parse the **superseded synthetic JSON** export model (ADR 0086 §2(a)) into the channel model.

    Kept working for the fixtures/tooling written against it before the real shape was known; the
    validated path is :func:`parse_package` (XML). :func:`parse_any` dispatches between them.

    Defensive throughout: a JSON syntax error or a structural violation raises
    :class:`CorepointImportError` (never an uncaught traceback), because the export is untrusted data.
    Returns one :class:`Channel` per exported channel."""
    # json's depth-limit RecursionError is a refusal too, not a raw traceback. Neither refusal chains
    # the decode error, which holds the whole export and its credentials (BACKLOG #2085); json's own
    # text is a fixed reason and a position, so it stays in the message.
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        refused: str | None = f"export is not valid JSON: {exc}"
    except RecursionError:
        refused = "export is nested too deeply to parse"
    else:
        refused = None
    if refused is not None:
        raise CorepointImportError(refused)
    if not isinstance(doc, dict):
        raise CorepointImportError("export root must be a JSON object")
    channels_raw = doc.get("channels")
    if not isinstance(channels_raw, list) or not channels_raw:
        raise CorepointImportError("export must carry a non-empty 'channels' array")

    channels: list[Channel] = []
    for i, ch in enumerate(channels_raw):
        if not isinstance(ch, dict):
            raise CorepointImportError(f"channel #{i} must be an object")
        channels.append(_parse_channel(ch, i))
    return tuple(channels)


def _parse_channel(ch: dict[str, Any], index: int) -> Channel:
    name = _req_str(ch, "name", f"channel #{index}")
    ident = _sanitize(name)

    inbound = ch.get("inbound")
    if not isinstance(inbound, dict):
        raise CorepointImportError(f"channel {name!r} requires an 'inbound' object")
    in_connector, in_call = _render_connector(inbound, name, inbound=True)

    # The export chooses this string, and it becomes BOTH the emitted ``inbound()`` connection name
    # and the module's filename stem (``import_corepoint`` writes ``out / f"{module_name}.py"``), so
    # it is untrusted text that reaches a filesystem write: fold it to a bare identifier, exactly as
    # the channel name above and the handler names below are folded. Mutation is right here rather
    # than a refusal, because the importer WRITES into a directory it created (it is not selecting an
    # existing file, so there is no basename-aliasing target to hand an attacker), and a fold that
    # collides with another channel's stem is already de-duplicated and reported by the writer's
    # ``assigned`` set. Sanitize at the source, not at the filename, so the stem and the connection
    # name it registers cannot desync.
    module_name = _connection_name(_sanitize(_opt_str(inbound, "name") or f"IB_{ident.upper()}"))

    dests_raw = ch.get("destinations", [])
    if not isinstance(dests_raw, list):
        raise CorepointImportError(f"channel {name!r} 'destinations' must be an array")
    destinations: list[Destination] = []
    for j, d in enumerate(dests_raw):
        if not isinstance(d, dict):
            raise CorepointImportError(f"channel {name!r} destination #{j} must be an object")
        d_connector, d_call = _render_connector(d, name, inbound=False)
        # Folded like the inbound name above, so the export cannot emit an ``outbound()`` the
        # loader refuses (BACKLOG #1107); handler ``destinations`` fold the same way to stay matched.
        d_name = _connection_name(_opt_str(d, "name") or _default_outbound(ident, j))
        destinations.append(Destination(d_name, d_connector, d_call))

    handlers_raw = ch.get("handlers")
    if not isinstance(handlers_raw, list) or not handlers_raw:
        raise CorepointImportError(f"channel {name!r} requires a non-empty 'handlers' array")
    all_dest_names = tuple(d.name for d in destinations)
    handlers: list[Handler] = []
    for k, h in enumerate(handlers_raw):
        if not isinstance(h, dict):
            raise CorepointImportError(f"channel {name!r} handler #{k} must be an object")
        handlers.append(_parse_handler(h, k, name, all_dest_names))

    router_name = _opt_str(ch, "router") or f"{ident.lower()}_router"
    return Channel(
        module_name, in_connector, in_call, router_name, tuple(destinations), tuple(handlers)
    )


def _default_outbound(ident: str, index: int) -> str:
    # Trim the stem, not the result, so a cap can never cut off the ``_<n>`` that keeps two unnamed
    # destinations of one channel apart.
    return f"OB_{ident.upper()[: _CONNECTION_NAME_BUDGET - 16]}_{index + 1}"


def _parse_handler(
    h: dict[str, Any], index: int, channel: str, all_dests: tuple[str, ...]
) -> Handler:
    raw_name = _opt_str(h, "name") or f"handler_{index + 1}"
    name = _sanitize(raw_name)
    actions_raw = h.get("actions", [])
    if not isinstance(actions_raw, list):
        raise CorepointImportError(
            f"channel {channel!r} handler {raw_name!r} 'actions' must be an array"
        )
    steps: list[Action | UnmappedAction] = []
    for a in actions_raw:
        if not isinstance(a, dict):
            raise CorepointImportError(
                f"channel {channel!r} handler {raw_name!r}: each action must be an object"
            )
        steps.append(_map_action(a))
    # A handler may target a subset of the channel's destinations; default to all of them.
    dests_raw = h.get("destinations")
    if dests_raw is None:
        dests = all_dests
    elif isinstance(dests_raw, list) and all(isinstance(x, str) for x in dests_raw):
        dests = tuple(_connection_name(x) for x in dests_raw)
    else:
        raise CorepointImportError(
            f"channel {channel!r} handler {raw_name!r} 'destinations' must be an array of names"
        )
    return Handler(name, tuple(steps), dests)


def _render_connector(spec: dict[str, Any], channel: str, *, inbound: bool) -> tuple[str, str]:
    """Render a connector spec to ``(connector_name, factory_call_source)``.

    Only ``mllp`` and ``file`` are modelled in the synthetic v1 schema; an unknown type is a structural
    error rather than a silent drop."""
    ctype = _req_str(spec, "connector", f"channel {channel!r} connector").lower()
    if ctype == "mllp":
        port = spec.get("port")
        if not isinstance(port, int) or isinstance(port, bool):
            raise CorepointImportError(
                f"channel {channel!r} mllp connector requires an integer 'port'"
            )
        if inbound:
            return "MLLP", f"MLLP(port={port})"
        host = _req_str(spec, "host", f"channel {channel!r} outbound mllp")
        return "MLLP", f"MLLP(host={_lit(host)}, port={port})"
    if ctype == "file":
        directory = _req_str(spec, "directory", f"channel {channel!r} file connector")
        if inbound:
            return "File", f"File(directory={_lit(directory)})"
        filename = _opt_str(spec, "filename")
        if filename is not None:
            return "File", f"File(directory={_lit(directory)}, filename={_lit(filename)})"
        return "File", f"File(directory={_lit(directory)})"
    raise CorepointImportError(
        f"channel {channel!r}: unknown connector type {ctype!r} (v1 supports 'mllp'/'file')"
    )


# --- the validated <Package> XML input layer ---------------------------------
#
# The real export is XML (see the module docstring). Everything below turns a ``<Package>`` into the
# SAME intermediate model the JSON layer produces, so the code generator is shared verbatim.

# Rich-text markup wrapper on ``@Data``. A Corepoint export stores each statement as *styled* text —
# syntax-colouring tags plus HTML entities, escaped again for the XML attribute. Strip the tags, then
# unescape the entities. Without this the leading token is a tag, not a verb, and the overwhelming
# majority of statements fail to classify: the single biggest schema surprise of the #105 validation.
_MARKUP_TAG = re.compile(r"<[^>]+>")


def strip_markup(data: str) -> str:
    """Recover the plain ``Verb operand …`` statement from a markup-wrapped ``@Data``/``@Comment``.

    Tag-strip first, then :func:`html.unescape` — that order is required, because the rich text
    double-escapes: an ``&amp;quot;`` in the file is a ``&quot;`` after the XML parse and a ``"`` only
    after the unescape. Unescaping first would resurrect ``<`` characters that the tag-strip would then
    eat out of the *statement*."""
    return html.unescape(_MARKUP_TAG.sub("", data)).strip()


# --- the ROLE layer: @Data markup is semantic, not decorative -----------------
#
# The rich-text wrapper on ``@Data`` does not merely colour the statement — each span carries a
# **semantic role class**, so the markup *is* the parse tree the exporter already computed. Flattening
# it (``strip_markup`` + :func:`tokenize_statement`) throws that away and fuses the operator's prose
# ``description`` into the statement, which is why a whitespace tokenizer sees hundreds of distinct
# shapes for one verb where the roles show a handful.
#
# Reading the roles instead is what makes operands recoverable: a ``path`` is addressed against the
# ``handle`` that precedes it, a ``literal`` is a value, a ``variable`` is a Corepoint variable, and
# ``detail``/``description`` are human text that must never be parsed as an operand.

# Tolerant of either quote style: the validated export writes ``class='keyword'``, but an exporter
# emitting double quotes must not silently fall out of the role layer (untrusted input, house rule).
# Spans NEST — the human ``detail`` label is written *inside* the ``path`` span it annotates — so the
# role scan is a stack, not a flat non-greedy match. Matching flatly folds the label into the path
# ("/PID-5-1 (Patient Name)"), which makes every path unresolvable for entirely the wrong reason.
_SPAN_OPEN = re.compile(r"<span\s+class=['\"]([A-Za-z-]+)['\"]\s*>")
_SPAN_CLOSE = re.compile(r"</span\s*>")

# Span class → the role this layer reasons about. Unlisted classes fall through to ``"text"`` so a
# future exporter class is inert rather than a crash — and is still visible in the token stream.
_ROLE_BY_CLASS = {
    "keyword": "keyword",  # the verb, and the grammar connectives the exporter styled
    "path": "path",  # a %tree/path operand
    "literal": "literal",  # a "quoted literal" value
    "variable": "variable",  # a $variable
    "input-handle": "handle",  # the action-list's INPUT message handle
    "other-handle": "handle",  # any other message handle (scratch/output)
    "numeral": "numeral",
    "detail": "detail",  # the human label rendered as "(...)" beside a path — NOT an operand
    "description": "description",  # the operator's trailing prose — NOT an operand
    "comment": "comment",
    "block": "block",
    "action-list-call-pass": "pass",
    "action-list-call-custom": "custom",
}

# Roles that are human text: they annotate the statement and must be dropped before operand matching
# (and re-emitted as a comment), never mistaken for a value.
_PROSE_ROLES = frozenset({"detail", "description", "comment"})


@dataclass(frozen=True)
class RoleToken:
    """One span of a markup-wrapped ``@Data``, tagged with the semantic role the exporter gave it.

    ``source_class`` keeps the raw span class, because ``input-handle`` and ``other-handle`` both map
    to the ``handle`` role but only the former identifies *the message this action-list transforms* —
    the distinction every genuine field mapping depends on."""

    role: str
    text: str
    source_class: str = ""


def parse_roles(data: str) -> tuple[RoleToken, ...]:
    """Split a markup-wrapped ``@Data`` into role-tagged tokens, in document order.

    Unspanned runs between spans become ``"text"`` tokens: those are the plain grammar connectives
    (``to``/``in``/``as``/``with``) the exporter did not style, and they carry the statement's shape.

    Each text run is attributed to its **innermost** enclosing span, so a ``detail`` label nested in a
    ``path`` span yields two tokens (the path, then its label) rather than one fused operand. The scan
    is tolerant by design: an unbalanced ``</span>`` simply pops to the enclosing role rather than
    raising, because the export is untrusted data.

    Returns ``()`` when the value carries no recognizable span at all, which is the caller's signal to
    fall back to the flat :func:`tokenize_statement` path (a synthetic or markup-free export)."""
    tokens: list[RoleToken] = []
    stack: list[str] = []
    saw_span = False
    pos = 0

    def flush(upto: int) -> None:
        run = strip_markup(data[pos:upto])
        if not run:
            return
        cls = stack[-1] if stack else ""
        tokens.append(RoleToken(_ROLE_BY_CLASS.get(cls, "text") if cls else "text", run, cls))

    while pos < len(data):
        opening = _SPAN_OPEN.search(data, pos)
        closing = _SPAN_CLOSE.search(data, pos)
        if opening is None and closing is None:
            break
        if closing is None or (opening is not None and opening.start() < closing.start()):
            assert opening is not None
            flush(opening.start())
            stack.append(opening.group(1).lower())
            saw_span = True
            pos = opening.end()
        else:
            flush(closing.start())
            if stack:
                stack.pop()
            pos = closing.end()
    if not saw_span:
        return ()
    flush(len(data))
    return tuple(tokens)


@dataclass(frozen=True)
class Operand:
    """One resolved operand of a statement — the unit a mapping matches against.

    ``kind`` is ``"path"`` (a message-tree address, always paired with the ``handle`` it is addressed
    against), ``"literal"``, ``"variable"``, or ``"numeral"``. ``primary`` marks a path addressed
    against the ``input-handle`` — the action-list's own message — which is the only case a
    :class:`Message` mutation can faithfully represent."""

    kind: str
    text: str
    handle: str = ""
    primary: bool = False
    # Whether a ``literal`` span carried its own quotes *inside* the span. The exporter is
    # inconsistent (most literals are wrapped, a large minority are bare), so the unwrap is
    # conditional and must happen exactly once — rendering a wrapped span verbatim would emit
    # ``set_field(msg, "MSH-6", "\"DEMO\"")``, a value carrying two stray quote characters.
    quoted: bool = False


def _literal_value(text: str) -> tuple[str, bool]:
    """``(value, was_quoted)`` for a ``literal`` span body.

    The exporter wraps most literal spans in their own quote characters and leaves a large minority
    bare, so the unwrap is **conditional and happens exactly once**: rendering a wrapped span verbatim
    puts two stray quotes inside the generated string. An unbalanced quote is not guessed — it comes
    back unwrapped so the caller can decline the statement rather than emit a half-stripped value."""
    if len(text) >= 2 and text.startswith('"') and text.endswith('"'):
        return text[1:-1], True
    return text, False


def _operands_from_roles(tokens: tuple[RoleToken, ...]) -> tuple[Operand, ...]:
    """Resolve role tokens into operands, pairing each ``path`` with the ``handle`` it follows.

    Prose roles are dropped (they annotate, they do not address anything) and ``text`` connectives are
    structural rather than operands. A ``handle`` with no following ``path`` is itself an operand — a
    whole-message reference, which is how ``MsgSend``/``MsgLog`` name their subject."""
    operands: list[Operand] = []
    pending: RoleToken | None = None
    for token in tokens:
        if token.role in _PROSE_ROLES or token.role == "text":
            continue
        if token.role == "handle":
            if pending is not None:
                operands.append(Operand("handle", pending.text, pending.text))
            pending = token
            continue
        if token.role == "path":
            handle = pending.text if pending is not None else ""
            primary = pending is not None and pending.source_class == "input-handle"
            operands.append(Operand("path", token.text, handle, primary))
            pending = None
            continue
        if pending is not None:
            operands.append(Operand("handle", pending.text, pending.text))
            pending = None
        if token.role == "literal":
            value, quoted = _literal_value(token.text)
            operands.append(Operand("literal", value, quoted=quoted))
        elif token.role in ("variable", "numeral"):
            operands.append(Operand(token.role, token.text))
    if pending is not None:
        operands.append(Operand("handle", pending.text, pending.text))
    return tuple(operands)


def _role_verb(tokens: tuple[RoleToken, ...]) -> str:
    """The statement's verb: the FIRST ``keyword`` span, or ``""`` when the statement leads with an
    operand (a ``$variable`` assignment) or carries no keyword at all."""
    for token in tokens:
        if token.role == "keyword":
            return token.text if _VERB.match(token.text) else ""
        if token.role in _PROSE_ROLES:
            continue
        if token.role in ("path", "literal", "variable", "handle", "numeral"):
            return ""  # leads with an operand — not a verb statement
    return ""


def _input_handle(action_list: Element) -> tuple[str, bool]:
    """The list's one ``input-handle``, which the Handler receives as ``msg``, or ``""``.

    A Corepoint action-list manipulates **several** messages at once (input, output, scratch), while a
    MessageFoundry Handler receives exactly **one** ``msg``. The input handle is the one the role
    markup tags ``input-handle``; every other handle starts out holding nothing the import can name,
    and gains a Python local only where :class:`_Flow` sees a clone or a ``MsgCreate`` bind it.

    The answer requires exactly one distinct ``input-handle`` name across the list's live elements.
    With none, or two, no handle is known to be ``msg``, so every field write and send that addresses
    the input fails closed. The scan skips ``@Disabled`` statements exactly where
    :func:`_parse_statement` does, so a switched-off line naming a second input does not count.

    The second value says whether any live element carries role markup at all. Only a list with none
    keeps the superseded model's reading, in which a markup-free field write lands on ``msg``."""
    inputs: set[str] = set()
    marked = False
    # A called list's own input handle is the message it was passed, not the caller's msg (see
    # _Flow._call), so an inlined ``<Call>`` body does not vote on the caller's input.
    called = {
        id(inner)
        for elem in _live_elements(action_list)
        if _local(elem.tag).lower() == "call"
        for inner in elem.iter()
        if inner is not elem
    }
    for elem in _live_elements(action_list):
        if id(elem) in called:
            continue
        data = _attr(elem, "Data")
        tokens = parse_roles(data) if data else ()
        marked = marked or bool(tokens)
        inputs.update(t.text for t in tokens if t.source_class == "input-handle")
    return (next(iter(inputs)) if len(inputs) == 1 else ""), marked


def _live_elements(action_list: Element) -> list[Element]:
    """Every element under ``action_list`` in document order, less each ``@Disabled`` subtree.

    A ``<List>``/``<Actions>`` wrapper is walked even when it carries ``@Disabled``, because
    :func:`_parse_list` flattens it and renders its statements live; the scan must see the same
    statements the render emits."""
    live: list[Element] = []
    stack = list(reversed(list(action_list)))
    while stack:
        elem = stack.pop()
        if _is_disabled(elem) and _local(elem.tag).lower() not in _LIST_TAGS:
            continue
        live.append(elem)
        stack.extend(reversed(list(elem)))
    return live


def _whole_tree(operand: Operand) -> str:
    """The handle ``operand`` names as a WHOLE message tree (``%OUT`` or ``%OUT/``), or ``""`` for
    anything else: a ``$variable``, a partial path, a literal."""
    if operand.kind == "handle":
        return operand.text
    if operand.kind == "path" and operand.handle and _is_root_path(operand.text):
        return operand.handle
    return ""


def _is_root_path(text: str) -> bool:
    """Whether a ``path`` span addresses a tree's ROOT (``/``) rather than a node inside it."""
    return not text.split(" (", 1)[0].strip().strip("/").strip()


def _role_prose(tokens: tuple[RoleToken, ...]) -> str:
    """The operator's own prose (``description``/``comment`` spans), joined — preserved as a comment.

    Kept separate from the statement so it is neither parsed as an operand nor silently discarded."""
    return " ".join(t.text for t in tokens if t.role in ("description", "comment") and t.text)


# XML element tags. Compared case-insensitively on the LOCAL name (a namespaced export yields
# ``{urn:…}List``), because the export is untrusted data and tolerant parsing is the house rule.
_LIST_TAGS = frozenset({"list", "actions"})
_CONTAINER_KIND_BY_TAG = {
    "block": "block",
    "call": "call",
    "case": "case",
    "foreach": "for",
    "if": "if",
    "loop": "while",
    "try": "try",
}
_STATEMENT_TAGS = frozenset({"line", *_CONTAINER_KIND_BY_TAG})

# Verbs that ARE control flow rather than a transform step. Keyed by the lower-cased verb so a
# ``<Line Data="ForEach …">`` (the verb carried on a plain line) lands on the same node as a
# ``<Foreach>`` element — the export uses both spellings for the same construct.
_KIND_BY_VERB = {
    "if": "if",
    "elseif": "elif",
    "else": "else",
    "foreach": "for",
    "loop": "while",
    "loopexit": "break",
    "try": "try",
    "catch": "except",
    "choosefrom": "case",
    "case": "case",
    "matching": "match",
    "msgsend": "send",
    "actionlistcall": "call",
    "returns": "exit",
    "actionlistexit": "exit",
    "actionliststop": "exit",
}

# Kinds that bind a message handle to a Python local; both render as ``<local> = <expression>``.
_BINDING_KINDS = frozenset({"clone", "create"})

# Kinds that continue an enclosing construct instead of standing alone, and what may adopt them.
_BRANCH_PARENT = {"elif": "if", "else": "if", "except": "try", "match": "case"}

# Kinds whose body is emitted INSIDE a Python block — under a dead placeholder condition, or in a loop
# that rewrites the same occurrence each pass. A statement anywhere beneath one of these is not
# unambiguous, so no field write may be emitted there (see :func:`_map_roles`).
_NESTING_KINDS = frozenset({"if", "elif", "else", "for", "while", "try", "except", "case", "match"})

# An HL7 field path in the ``SEG-F[.C[.S]]`` grammar :class:`Message` understands.
_HL7_PATH = re.compile(r"^[A-Za-z0-9]{3}-\d+(?:\.\d+){0,2}$")


def _local(tag: str) -> str:
    """The local name of a (possibly namespaced) XML tag: ``{urn:x}List`` → ``List``."""
    return tag.rsplit("}", 1)[-1]


def _attr(elem: Element, name: str) -> str:
    """Case-insensitively read attribute ``name``, or ``""``. Untrusted input: never assume casing."""
    lowered = name.lower()
    for key, value in elem.attrib.items():
        if _local(key).lower() == lowered:
            return value
    return ""


def _disabled_scope(elem: Element, parents: dict[Element, Element]) -> tuple[str, str] | None:
    """``(tag, label)`` of the nearest ``@Disabled`` self-or-ancestor of ``elem``, else ``None``.

    ``@Disabled`` switches off a whole **subtree**, so an ``<ActionList>`` — or the ``<Package>`` around
    it — carrying the attribute switches off every statement beneath it. The statement-level check in
    :func:`_parse_statement` never sees those elements (it only runs on the statement children of a
    ``<List>``), so without this walk an action-list an operator switched OFF before exporting came back
    ON as live code, with a live ``MsgSend``, a declared outbound and a summary reporting zero disabled
    — the exact accept-and-drop inversion ``@Disabled`` must never produce."""
    node: Element | None = elem
    while node is not None:
        if _is_disabled(node):
            return _local(node.tag), _attr(node, "Name") or _attr(node, "Desc")
        node = parents.get(node)
    return None


def _is_disabled(elem: Element) -> bool:
    """Whether ``@Disabled`` marks this element (and its whole subtree) as not-live.

    Present-and-not-falsey wins: exporters write ``Disabled="1"``/``"true"``/``"yes"``, and a bare
    ``Disabled=""`` is treated as absent so an empty attribute cannot silently kill live code."""
    return _attr(elem, "Disabled").strip().lower() not in ("", "0", "false", "no")


def tokenize_statement(statement: str) -> list[str]:
    """Split a markup-stripped statement into ``Verb`` + operand tokens.

    Whitespace separates tokens *except* inside a ``"string literal"``, a ``[bracketed option]``, or a
    ``(parenthesised condition)`` — the grouping forms of the validated grammar — so a condition or a
    literal containing spaces survives as one token. Depth-tracked rather than regex-matched, so a
    nested ``(a (b))`` does not terminate early. Tolerant by design: an unbalanced quote/bracket ends
    at the statement rather than raising, because the export is untrusted data."""
    tokens: list[str] = []
    buf: list[str] = []
    parens = 0
    brackets = 0
    in_quote = False
    for ch in statement:
        if in_quote:
            buf.append(ch)
            in_quote = ch != '"'
            continue
        if ch == '"':
            in_quote = True
        elif ch == "(":
            parens += 1
        elif ch == ")":
            parens = max(0, parens - 1)
        elif ch == "[":
            brackets += 1
        elif ch == "]":
            brackets = max(0, brackets - 1)
        elif ch.isspace() and parens == 0 and brackets == 0:
            if buf:
                tokens.append("".join(buf))
                buf = []
            continue
        buf.append(ch)
    if buf:
        tokens.append("".join(buf))
    return tokens


_VERB = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")


def _split_verb(statement: str) -> tuple[str, list[str]]:
    """``(verb, operands)`` for a stripped statement; ``verb`` is ``""`` when the head is not a verb."""
    tokens = tokenize_statement(statement)
    if not tokens or not _VERB.match(tokens[0]):
        return "", tokens
    return tokens[0], tokens[1:]


def _message_path(token: str) -> str | None:
    """Recover an HL7 ``SEG-F[.C[.S]]`` path from a ``%tree/path`` operand, or ``None``.

    A Corepoint ``%`` operand addresses a node in a *named message tree*; only the leaf carries the HL7
    coordinates, so the last path segment is what :class:`Message` can address (``%ADT/PID-5.1`` →
    ``PID-5.1``). Anything that does not land on the HL7 grammar — a named tree node, a ``$variable``,
    a literal — returns ``None`` and the statement degrades to a TODO. **Never guess a path**: a wrong
    path silently writes the wrong field, which is worse than an unmapped marker (count-and-log)."""
    if not token.startswith("%"):
        return None
    leaf = token[1:].split("/")[-1]
    return leaf if _HL7_PATH.match(leaf) else None


# A Corepoint path LEAF: a 3-character segment id followed by hyphen-separated coordinates. Corepoint
# writes ``PID-5-1`` where :class:`Message` writes ``PID-5.1`` — the same address in a different
# punctuation, so the translation is mechanical and faithful (never a guess). Getting this wrong is
# what made every path look unresolvable: nothing in the export is dot-separated.
_COREPOINT_LEAF = re.compile(r"^([A-Za-z0-9]{3})((?:-\d+){1,3})$")
# A bare segment reference (``/OBX``) — not a field address, but what ForEach/MsgTreeCopy iterate over.
_COREPOINT_SEGMENT = re.compile(r"^[A-Za-z0-9]{3}$")


def _path_leaf(text: str) -> str:
    """The addressable leaf of a ``path``-span body, with the exporter's human label removed.

    A path span carries its own label as *unspanned* text inside the span (``/PID-5-1 (Patient Name)``)
    — the parenthetical is display text, not part of the address, so it is cut before the leaf is read.
    Without the cut every path looks like an unresolvable named node."""
    body = text.split(" (", 1)[0]
    return body.strip().strip("/").split("/")[-1].strip()


def _corepoint_path(text: str) -> str | None:
    """Translate a Corepoint ``path``-span body into a :class:`Message` ``SEG-F[.C[.S]]`` path.

    The span body is a tree address (``/PID-5-1``, ``/Patient/Name``); only the **leaf** carries HL7
    coordinates, and only when it is a segment id plus 1–3 hyphen-separated numbers. A named tree node
    (``/Patient/Name``), a bare segment, or anything else returns ``None`` so the statement degrades to
    a TODO — :func:`_message_path`'s rule that a wrong path is worse than a marker still governs."""
    leaf = _path_leaf(text)
    if _HL7_PATH.match(leaf):  # already dotted (a tolerant exporter, or the synthetic model)
        return leaf
    match = _COREPOINT_LEAF.match(leaf)
    if match is None:
        return None
    coords = match.group(2).split("-")[1:]
    return f"{match.group(1)}-{coords[0]}" + ("." + ".".join(coords[1:]) if len(coords) > 1 else "")


def _corepoint_segment(text: str) -> str | None:
    """The segment id a ``path`` span addresses when it names a whole segment (``/OBX``), else ``None``."""
    leaf = _path_leaf(text)
    return leaf.upper() if _COREPOINT_SEGMENT.match(leaf) else None


def _string_literal(token: str) -> str | None:
    """The inner text of a ``"quoted literal"`` operand, or ``None`` when the token is not one."""
    if len(token) >= 2 and token.startswith('"') and token.endswith('"'):
        return token[1:-1]
    return None


def _option(token: str) -> str | None:
    """The inner text of a ``[bracketed option]`` operand, or ``None``."""
    if len(token) >= 2 and token.startswith("[") and token.endswith("]"):
        return token[1:-1].strip() or None
    return None


def _first_path(operands: list[str]) -> str | None:
    """The first operand that resolves to an HL7 path — the intended target named in a TODO marker."""
    for token in operands:
        path = _message_path(token)
        if path is not None:
            return path
    return None


def _map_statement(verb: str, operands: list[str], statement: str) -> Action | UnmappedAction:
    """Map one *executable* statement onto the v1 vocabulary, or degrade it to an :class:`UnmappedAction`.

    Deliberately narrow: a verb maps only where the vocabulary helper is a genuine equivalent **and**
    every operand resolves (an HL7 path for a field, a quoted literal for a value). A ``$variable``
    operand, a whole-subtree copy (``MsgTreeCopy``), a message lifecycle/logging/alerting verb, or a
    resolvable-looking-but-not-HL7 tree path all fall through to the TODO marker rather than emit code
    that would be confidently wrong."""
    if verb == "ItemCopy" and len(operands) == 2:
        dst = _message_path(operands[1])
        if dst is not None:
            src = _message_path(operands[0])
            if src is not None:
                return Action(verb, "copy_field", (_lit(src), _lit(dst)))
            literal = _string_literal(operands[0])
            if literal is not None:
                # A literal source is a set, not a copy — the same statement Corepoint writes as a copy
                # from a constant. ``set_field`` is the exact vocabulary equivalent.
                return Action(verb, "set_field", (_lit(dst), _lit(literal)))
    elif verb == "ItemClear" and len(operands) == 1:
        target = _message_path(operands[0])
        if target is not None:
            # Clearing a field is exactly setting it empty (``Message.set`` re-encodes structurally).
            return Action(verb, "set_field", (_lit(target), _lit("")))
    elif verb == "ItemAppend" and len(operands) == 2:
        target = _message_path(operands[0])
        suffix = _string_literal(operands[1])
        if target is not None and suffix is not None:
            return Action(verb, "append_to_field", (_lit(target), _lit(suffix)))

    reason = (
        f"no v1 vocabulary mapping for Corepoint {verb}"
        if verb
        else "statement does not begin with a verb"
    )
    # The recovered target rides into the marker text, exactly as on the validated role-parsed path
    # (:func:`_decline`) — never into a live ``msg.set`` line. It goes AHEAD of the quoted statement
    # because the statement is the unbounded part: :func:`_generate_steps` elides the marker, and the
    # target is the half a migrator cannot reconstruct from the export by eye.
    target = _first_path(operands)
    lead = f"{reason}; intended target {target}" if target is not None else reason
    return UnmappedAction(verb or "<unparsed>", f"{lead}: {statement}")


def _field_of(operand: Operand, live: Mapping[str, str]) -> str | None:
    """The :class:`Message` path this operand addresses on a handle with a live local, or ``None``.

    Three conditions, all required: the operand is a path, the handle it addresses holds a message
    the import can name at this point (``live``, from :class:`_Flow`), and its leaf resolves to HL7
    coordinates. Relaxing any one of them produces code that writes a real field of the wrong
    message, or the wrong field — the failure mode this importer exists to avoid."""
    if operand.kind != "path" or operand.handle not in live:
        return None
    return _corepoint_path(operand.text)


def _decline_reason(operands: tuple[Operand, ...], live: Mapping[str, str]) -> str:
    """Why a role-parsed statement could not be mapped — named precisely so a human can act on it.

    A generic "no mapping" marker makes 5,000 TODOs look identical; naming the *cause* is what lets a
    migrator triage them (a cross-message write needs its tree built first; an unresolvable node path
    needs a field decision; a variable needs hand-written Python)."""
    paths = [o for o in operands if o.kind == "path"]
    if not live and paths:
        return (
            "no handle in this action-list holds a message this import can identify at this point"
        )
    if any(o.handle not in live for o in paths):
        return (
            "addresses a message handle that holds no message this import can identify at this "
            "point (cross-message)"
        )
    if any(_corepoint_path(o.text) is None for o in paths):
        return "path names a message-tree node with no HL7 field coordinates"
    if any(o.kind == "variable" for o in operands):
        return "operand is a Corepoint $variable, which has no Handler equivalent"
    resolved = [p for p in (_corepoint_path(o.text) for o in paths) if p is not None]
    if any(p in _FRAMING_PATHS for p in resolved):
        return (
            "targets MSH-1/MSH-2 (field separator / encoding characters) — Message.set accepts the "
            "path but rewrites one glyph and leaves the rest of the line on the old one"
        )
    if any(p.split("-", 1)[0].upper() not in _SINGLE_OCCURRENCE for p in resolved):
        return (
            "segment can repeat and the Corepoint path carries no occurrence — Message.set would "
            "always write the first; confirm which occurrence was meant"
        )
    return "no v1 vocabulary mapping"


# Segments HL7 defines as occurring at most once per message. A Corepoint path carries no occurrence
# subscript — occurrence is implied by the enclosing loop — while ``Message.set`` always writes the
# FIRST occurrence. So a write is only unambiguous on a segment that cannot repeat; on a repeating one
# (OBX, NK1, DG1, …) the importer would silently pick occurrence 1. Deliberately a small allowlist:
# being absent from it costs a TODO marker, being wrongly in it costs a silently misplaced value.
_SINGLE_OCCURRENCE = frozenset(
    {"MSH", "EVN", "PID", "PD1", "PV1", "PV2", "MRG", "ACC", "UB1", "UB2"}
)

# ``MSH-1``/``MSH-2`` are the field separator and the encoding characters. ``Message.set`` accepts both
# and rewrites the glyph in place while the rest of the line keeps the old one, producing a message
# with mixed delimiters — corruption that parses. Never emit a write to either.
_FRAMING_PATHS = frozenset({"MSH-1", "MSH-2"})

# The connectives each mappable verb is allowed to carry. Anything outside its set means the statement
# said something the mapping does not model, so the statement is declined rather than approximated.
_VERB_CONNECTIVES = {
    "itemcopy": frozenset({"to"}),
    "itemclear": frozenset[str](),
    "itemappend": frozenset({"to"}),
}


def _writable(path: str | None) -> bool:
    """Whether a resolved path may be *written* — single-occurrence segment, never the framing fields."""
    if path is None or path in _FRAMING_PATHS:
        return False
    return path.split("-", 1)[0].upper() in _SINGLE_OCCURRENCE


def _map_roles(
    verb: str,
    operands: tuple[Operand, ...],
    live: Mapping[str, str],
    *,
    words: tuple[str, ...],
    qualified: bool,
    in_control: bool,
) -> Action | UnmappedAction | None:
    """Map a **role-parsed** statement onto the vocabulary, or ``None`` to decline.

    Declining is the common, correct outcome: the caller turns it into a TODO marker carrying
    :func:`_decline_reason`. Only genuine equivalences are emitted — the operand order follows the
    export's own ``<source> to <destination>`` grammar, which is the reverse of the superseded JSON
    model's ``(target, value)`` argument order for ``ItemAppend``."""
    lowered = verb.lower()
    allowed = _VERB_CONNECTIVES.get(lowered)
    if allowed is None:
        return None
    # Guards that apply to every field write, checked before any per-verb shape.
    if qualified or not {w.lower() for w in words} <= allowed:
        return None
    if in_control:
        # Inside an If/ForEach/Loop/Try the statement is conditional or repeated in the SOURCE, but the
        # emitted condition is a dead placeholder and the loop is `for _item in []`. A real call there
        # would run under a condition nobody wrote — and in a loop it would rewrite occurrence 1 every
        # pass. Only a top-level statement is unambiguous, so only a top-level statement maps.
        return None

    if lowered == "itemcopy" and len(operands) == 2:
        dst = _field_of(operands[1], live)
        if _writable(dst):
            assert dst is not None
            if operands[0].kind == "literal" and operands[0].quoted:
                # A constant source is a set, not a copy — the vocabulary's exact equivalent. Only a
                # QUOTED literal is taken: a bare literal span is the exporter's un-delimited form and
                # its extent is not reliably recoverable.
                return Action(
                    verb,
                    "set_field",
                    (_lit(dst), _lit(operands[0].text)),
                    target=live[operands[1].handle],
                )
            src = _field_of(operands[0], live)
            if src is not None:
                # NOT mapped to ``copy_field``: it writes "" when the source is absent, which would
                # CLEAR a populated destination, and nothing in the export says Corepoint does that
                # rather than leave the destination untouched. Declined deliberately (see _decline).
                return None
    elif lowered == "itemclear" and len(operands) == 1:
        target = _field_of(operands[0], live)
        if _writable(target):
            assert target is not None
            # Clearing is setting empty; ``Message.set`` re-encodes structurally.
            return Action(
                verb, "set_field", (_lit(target), _lit("")), target=live[operands[0].handle]
            )
    elif lowered == "itemappend" and len(operands) == 2:
        # ``ItemAppend "<suffix>" to <target>`` — value FIRST, target second.
        target = _field_of(operands[1], live)
        if _writable(target) and operands[0].kind == "literal" and operands[0].quoted:
            assert target is not None
            return Action(
                verb,
                "append_to_field",
                (_lit(target), _lit(operands[0].text)),
                target=live[operands[1].handle],
            )
    return None


def _decline(verb: str, operands: tuple[Operand, ...], live: Mapping[str, str]) -> UnmappedAction:
    """Turn a declined role-parsed statement into a TODO marker that says *why*, and emits no code.

    The recovered target is the first operand that is genuinely ``msg``'s own field, so the hand-finish
    keeps the intended field visible without inventing one when nothing resolves."""
    # NO live stub. The "best-effort passthrough" ``msg.set(p, msg.field(p) or "")`` is not the inert
    # marker its comment claimed: ``Message.set`` RAISES ``KeyError`` on an absent segment, and on a
    # present segment with an absent field it *materialises* the field and its empty components on the
    # wire. A line whose only job is to stay visible must not be able to change the message or
    # dead-letter it, so the recovered target rides into the comment instead. Every other
    # ``UnmappedAction`` site now does the same (#1681); this one did it first.
    target = next(
        (field for field in (_field_of(o, live) for o in operands) if field is not None),
        None,
    )
    reason = _decline_reason(operands, live)
    detail = f"{reason}; intended target {target}" if target else reason
    return UnmappedAction(verb, detail)


def _role_send_args(operands: tuple[Operand, ...]) -> tuple[str, ...]:
    """The rendered destination-name literal for a role-parsed ``MsgSend``, or ``()``.

    The validated grammar is ``MsgSend <handle> to connection "<name>"``, so the destination is the
    statement's first **literal** — precise where the flat heuristic had to guess at the first quoted
    token. Sanitized in one place, exactly as :func:`_send_args`, so a hostile name cannot ride into the
    generated wiring as a traversal path."""
    for operand in operands:
        if operand.kind == "literal" and operand.text.strip():
            return (_lit(_connection_name(_sanitize(operand.text))),)
    return ()


def _send_refusal(sent: str, live: Mapping[str, str]) -> str:
    """Why a ``MsgSend`` of handle ``sent`` (``""`` when it names none) must not render, or ``""``.

    A Handler can send any Message it holds, but the import knows what a handle holds only where
    :class:`_Flow` saw it bound: the input handle is ``msg``, and a clone or a ``MsgCreate`` binds
    another handle to its own local. A send of anything else would have to guess, and the old guess,
    ``msg``, delivered the unmodified input in place of the message Corepoint built. So the render
    raises at the send site instead (BACKLOG #313). Dropping the send would make the handler filter
    silently.

    It fails CLOSED. A ``$variable``, a partial path, no handle at all, and a handle bound on only
    some of the paths that reach the send are all refused. The markup-free reading is judged the
    same way, from the handle its first operand names. The handle is untrusted and unbounded, so it
    is flattened and elided before it enters the text."""
    if sent and sent in live:
        return ""
    refuse = "the import refuses to send msg in its place"
    if not sent:
        return f"MsgSend names no message handle this import can identify; {refuse}"
    handle = _comment_text(sent, 60)
    if not live:
        return (
            f"MsgSend delivers {handle}, and no handle in this action-list holds a message this "
            f"import can identify at this point (it has no single input handle, or another tree "
            f"overwrote it); {refuse}"
        )
    return (
        f"MsgSend delivers {handle}, which at this point is not the input handle, nor bound by a "
        f"whole-tree clone or a MsgCreate on every path before this send; {refuse}"
    )


def _split_branches(steps: list[Step]) -> tuple[tuple[Step, ...], tuple[Control, ...]]:
    """Split a container body at its branch markers into ``(body, branches)``.

    The export writes ``Else``/``ElseIf``/``Catch``/``Matching`` as ordinary statements *inside* the
    construct's own ``<List>``, so everything after such a marker belongs to that branch. Walk once
    to keep successive branches siblings without consuming stack space for a wide list."""
    body: tuple[Step, ...] = ()
    branches: list[Control] = []
    marker: Control | None = None
    start = 0
    for i, step in enumerate(steps):
        if isinstance(step, Control) and step.kind in _BRANCH_PARENT and not step.body:
            if marker is None:
                body = tuple(steps[:i])
            else:
                branches.append(replace(marker, body=tuple(steps[start:i])))
            marker = step
            start = i + 1
    if marker is None:
        return tuple(steps), ()
    branches.append(replace(marker, body=tuple(steps[start:])))
    return body, tuple(branches)


# How deep the ``<List>`` tree may nest. The walk is mutually recursive (list → statement → list), so
# an untrusted export nesting thousands of elements would otherwise exhaust the interpreter stack and
# surface as a RecursionError traceback instead of a clean, reported error (CLAUDE.md §6/§8). Real
# packages nest a handful of levels; 100 is far past any plausible hand-authored action-list.
#
# This bounds DEPTH only, not the WIDTH of one branch list, and width has its own bound the fix for the
# earlier recursion-on-width defect moved rather than removed: ``generate_module`` renders one ``elif
# False:`` per sibling branch (see the ``If``/``ChooseFrom`` renderer below) into the generated module's
# source text, and past roughly 5,950 to 5,960 siblings CPython's own parser raises ``MemoryError:
# Parser stack overflowed``. Two independent instruments put the edge in that band: a bisect over the
# real generator and a bisect over synthetic source, landing one apart, the difference explained by how
# much nesting frames the branch list. Treat it as a band and not a constant -- it moves with nesting
# depth, and it belongs to the CPython build rather than to this module, so never assert an exact width.
#
# The accept-and-drop this used to describe is FIXED: ``import_corepoint`` now compiles every generated
# module before writing it (:func:`_verify_compilable`), so crossing the wall is a reported
# ``CorepointImportError`` and a non-zero exit instead of a bad file written under a success report.
# WHETHER TO BOUND BRANCH WIDTH WAS THE OPEN QUESTION, AND IT IS ANSWERED: DO NOT. The fear was that
# a limit low enough to stay clear of the wall would refuse a legitimate long ``ElseIf`` chain. That
# is a claim about how wide a REAL export gets, which nobody had measured -- the wall was quoted
# precisely while the number that actually decides the question was assumed. Measured 2026-09-21
# against a real production Corepoint export (4.3 MB, roughly 500x the test fixture), walked with
# this module's own ``parse_package``: 206 branching constructs, WIDEST SIBLING CHAIN 5, median 2,
# the ten widest all between 3 and 5. Against a wall near 5,950 that is about three orders of
# magnitude of headroom, so a width bound would protect nothing and is not worth its risk.
#
# n=1: one export from one site, and it is the only real one that was available. The conclusion
# survives a site two orders of magnitude wider, but do not read 5 as a surveyed maximum -- it is one
# measurement, and a second export is what would upgrade it.
#
# The guard that DOES matter is the post-condition above, which is not a limit at all: it refuses
# nothing legitimate and fires only on source this module could not itself parse.
_MAX_NESTING = 100


def _parse_list(container: Element, in_control: bool, depth: int = 0) -> list[Step]:
    """Parse the statement children of a ``<List>``/``<Actions>`` into ordered steps.

    A branch marker that follows a compatible construct as a *sibling* is adopted by it; the more
    common in-body form is handled by :func:`_split_branches` when the construct is built."""
    if depth > _MAX_NESTING:
        raise CorepointImportError(
            f"export nests statements more than {_MAX_NESTING} levels deep — refusing to parse"
        )
    steps: list[Step] = []
    for child in container:
        tag = _local(child.tag).lower()
        if tag in _LIST_TAGS:
            # A doubly-wrapped list: flatten rather than lose the statements.
            steps.extend(_parse_list(child, in_control, depth + 1))
            continue
        # EVERY other child is a statement position and goes through _parse_statement — including a tag
        # this layer does not model, which comes back as an "unknown" marker plus its parsed subtree.
        # Skipping unmodelled tags here (as an earlier cut did, citing the <Connection>/<Codeset>/
        # <DataPoint> package subtrees) dropped whole subtrees silently: those subtrees are children of
        # <Package>, NEVER of a <List>, so the tolerance was applied exactly where statements live and a
        # <Switch> — or a <Lines> typo — vanished with its body. Untrusted input is still never a crash.
        produced = _parse_statement(child, in_control, depth + 1)
        if (
            len(produced) == 1
            and isinstance(produced[0], Control)
            and produced[0].kind in _BRANCH_PARENT
            and steps
            and isinstance(steps[-1], Control)
            and steps[-1].kind == _BRANCH_PARENT[produced[0].kind]
        ):
            previous = steps[-1]
            steps[-1] = replace(previous, branches=(*previous.branches, produced[0]))
            continue
        steps.extend(produced)
    return steps


def _container_steps(elem: Element, in_control: bool, depth: int = 0) -> list[Step]:
    """The nested body of ``elem``, in document order — every child, whatever shape it takes.

    :func:`_parse_list` already flattens a ``<List>``/``<Actions>`` wrapper, so walking ``elem`` itself
    covers BOTH forms (the usual wrapped body and a direct statement child) *and* keeps a statement that
    is a **sibling** of the wrapper. Returning only the wrapper's children — as an earlier cut did the
    moment any wrapper existed — silently discarded those siblings, including an ``Else`` marker and its
    whole branch body."""
    return _parse_list(elem, in_control, depth + 1)


def _parse_statement(elem: Element, in_control: bool, depth: int = 0) -> list[Step]:
    """Parse one statement element into zero or more steps (a list, so a leaf can carry a body).

    A statement whose rendering depends on what a message handle holds at that point comes back as a
    ``"pending"`` node (or a ``"send"`` carrying its operands); :class:`_Flow` settles both in
    statement order once the whole tree is parsed (BACKLOG #313, step 2)."""
    tag = _local(elem.tag)
    data = _attr(elem, "Data")
    statement = strip_markup(data)
    note = strip_markup(_attr(elem, "Comment"))
    # The role layer is the primary reading; the flat tokenizer stays the fallback for a markup-free
    # export (the superseded synthetic model, and any exporter that writes plain @Data).
    roles = parse_roles(data)
    flat_verb, operands = _split_verb(statement)
    # Unspanned runs and ``detail`` spans are NOT inert decoration: measured against the export they
    # carry comparison operators (``=``/``<>``/``contains``) and mode flags ("replace all", "interpret
    # escapes"). A mapping may only fire when the statement's words (see :func:`_statement_words`,
    # unspanned or styled as a keyword) fall inside that verb's known set and it carries no qualifier —
    # otherwise the emitted call would silently lose an operator.
    qualified = any(t.role == "detail" for t in roles)
    verb = _statement_verb(roles, flat_verb)
    role_operands = _operands_from_roles(roles) if roles else ()

    source = _source_label(tag, verb)
    kind = _statement_kind(tag, verb)

    # A construct NESTS its body under a placeholder condition; a ``<Block>``/``<Call>`` is a label
    # whose body stays at the same indentation, so it does not deepen control scope.
    body = _container_steps(elem, in_control or kind in _NESTING_KINDS, depth)
    # The handle operands, read the same way for both layers, so a markup-free statement is judged
    # by the same flow rules as a role-parsed one. A role reading that found no operand at all (its
    # spans carry classes the role layer does not list) falls back to the flat reading.
    flat_operands = _flat_operands(operands)
    handle_operands = role_operands or flat_operands
    named = frozenset(h for h in map(_whole_tree, (*role_operands, *flat_operands)) if h)
    words = _statement_words(roles, verb)

    if _is_disabled(elem):
        # Preserved in full as commented-out pseudo-source — the subtree is parsed (so it is visible and
        # counted) but is never emitted as live code.
        label = statement or note or tag
        return [Control("disabled", source, label, body=tuple(body))]

    if tag.lower() not in _STATEMENT_TAGS:
        # An element in a statement position whose tag this layer does not model. Reported and counted,
        # with its parsed subtree inlined beneath the marker — never dropped (count-and-log). The marker
        # says the element's SCOPE was lost, because an unmodelled construct may well have been
        # conditional: inlining its body is the honest, visible degradation, guessing the scope is not.
        # The element still ran in Corepoint, so its own whole-tree writes are carried for the flow.
        deferred = (
            _Deferred(verb, handle_operands, qualified=qualified, named=named, words=words)
            if named
            else None
        )
        return [Control("unknown", tag, statement or note, body=tuple(body), deferred=deferred)]

    if not data and any(isinstance(s, Control) and s.kind == kind for s in body):
        # A **branch-group wrapper**: the validated export writes ``<If>``/``<Try>`` with no ``@Data``
        # at all, holding one child per branch (``<Line Data="If (…)">``, ``<Line Data="Else">``,
        # ``<Line Data="Catch">``) that each carry their OWN condition and their OWN body. Emitting a
        # construct for the wrapper too produced a second, condition-less ``if False:`` around an
        # already-complete chain — 757 of them, every one counted as a mapped step it never was.
        #
        # The test is that the body ALREADY contains the same construct, not merely that the element
        # has no ``@Data``: an exporter that puts the condition on the container and the statements
        # directly beneath it (the shape the synthetic fixture models) has no inner construct to
        # inherit, and passing that through would delete the try/except or the if entirely.
        return list(body)

    if kind is None:
        mapped: Step
        if roles and verb:
            # Which handle each operand addresses holds a known message only at some points, so the
            # mapping waits for :class:`_Flow`, which walks the statements in order.
            mapped = Control(
                "pending",
                verb,
                statement,
                deferred=_Deferred(
                    verb,
                    role_operands,
                    qualified=qualified,
                    in_control=in_control,
                    named=named,
                    words=words,
                    styled=bool(_role_verb(roles)),
                ),
            )
        elif statement:
            # The markup-free reading maps without handles. The flow still decides which local a
            # mapped write lands on, and sees any whole-tree write it makes.
            flat = _map_statement(verb, operands, statement)
            mapped = Control(
                "pending",
                verb,
                statement,
                deferred=_Deferred(
                    verb, flat_operands, in_control=in_control, flat=flat, named=named
                ),
            )
        else:
            # No statement at all — reported rather than skipped, because a silently-ignored element is
            # exactly the accept-and-drop this importer refuses (count-and-log).
            mapped = UnmappedAction(tag, f"<{tag}> carries no statement to translate")
        # An operator's ``@Comment`` — and the ``description``/``comment`` prose the role layer lifts
        # OUT of the statement — is preserved beside the step it annotates, never dropped.
        prose = note or _role_prose(roles)
        lead: list[Step] = [Control("block", "Comment", prose)] if prose else []
        return [*lead, mapped, *body]

    if kind == "send":
        # ``*body`` matters: a ``MsgSend`` element that carries a nested list would otherwise lose it
        # (the break/exit path below always kept its body — this one silently did not). Whether the
        # handle it names holds a known message is the flow's question, settled in statement order.
        args = _role_send_args(role_operands) if roles else _send_args(operands)
        deferred = _Deferred(verb, handle_operands, named=named)
        return [Control("send", source, statement, args=args, deferred=deferred), *body]
    if kind in ("break", "exit"):
        return [Control(kind, source, statement), *body]
    if kind in ("block", "call"):
        # A ``<Block>`` is a section LABEL, not an action, and a ``<Call>``'s target list is inlined:
        # both emit a comment plus their body at the SAME indentation — never a step of their own.
        # What a call may reach is judged by :meth:`_Flow._call` from the call line's raw text.
        return [Control(kind, source, statement or note or tag, body=tuple(body))]

    inner, branches = _split_branches(body)
    detail = _strip_leading_verb(statement, verb)
    return [Control(kind, source, detail, body=inner, branches=branches)]


def _statement_verb(roles: tuple[RoleToken, ...], flat_verb: str) -> str:
    """A statement's verb, read the same way for every statement :func:`_parse_statement` builds.

    Prefer the role layer's verb, but keep the flat reading as a NAMING fallback: a handful of verbs
    are not styled as a ``keyword`` span at all, and letting those collapse into "<unparsed>" would
    throw away the one thing that makes a TODO triageable — which verb it was."""
    return (_role_verb(roles) or flat_verb) if roles else flat_verb


def _statement_words(roles: tuple[RoleToken, ...], verb: str) -> tuple[str, ...]:
    """The statement's words that are neither an operand nor the verb, in order.

    The exporter styles some connectives as ``keyword`` spans and leaves others as unspanned text, so
    both count: a ``from`` styled as a keyword reverses a copy exactly as an unstyled one does. The
    verb is dropped whichever way it was written, so an unstyled verb is not read as a word."""
    words: list[str] = []
    verb_seen = False
    for token in roles:
        if token.role not in ("text", "keyword"):
            continue
        for word in token.text.split():
            if not verb_seen and word.lower() == verb.lower():
                verb_seen = True
                continue
            words.append(word)
    return tuple(words)


def _statement_kind(tag: str, verb: str) -> str | None:
    """The control kind a statement element renders as, or ``None`` for a transform statement."""
    kind = _CONTAINER_KIND_BY_TAG.get(tag.lower())
    if kind is None:
        # A ``<Line>``: control flow is carried by the verb, everything else is a transform statement.
        return _KIND_BY_VERB.get(verb.lower())
    if kind in ("block", "call") and verb.lower() in _KIND_BY_VERB:
        # ``<Call Data="ActionListCall …">`` — the verb is the more specific truth.
        return _KIND_BY_VERB[verb.lower()]
    return kind


def _source_label(tag: str, verb: str) -> str:
    """The provenance name a step reports: the control verb when there is one, else the element tag.

    A ``<Block Data="Patient identity">`` has no verb at all — its ``@Data`` is prose — so the label
    must fall back to the tag rather than mistake the first word of a section title for a verb."""
    if verb and verb.lower() in _KIND_BY_VERB:
        return verb
    if tag.lower() == "line":
        return verb or tag
    return tag


def _strip_leading_verb(statement: str, verb: str) -> str:
    """Drop the leading control verb so ``detail`` carries only the condition/operands."""
    if verb and statement[: len(verb)].lower() == verb.lower():
        return statement[len(verb) :].strip()
    return statement


def _send_args(operands: list[str]) -> tuple[str, ...]:
    """The rendered destination-name literal for a ``MsgSend``, or ``()`` when none is recoverable.

    Sanitized at recovery, in one place, so the SAME safe name is used as the connection id, as the
    ``Send`` target, and as the placeholder endpoint's directory leaf — an untrusted export naming a
    destination ``../../etc`` must not put a traversal path into the generated wiring."""
    for token in operands:
        name = _option(token) or _string_literal(token)
        if name:
            return (_lit(_connection_name(_sanitize(name))),)
    return ()


def _flat_operands(tokens: list[str]) -> tuple[Operand, ...]:
    """Read the markup-free operands as the role layer would, for the handle questions only.

    A ``%NAME`` or ``%NAME/`` token is a whole message handle and ``%NAME/path`` a path addressed
    against it; a ``$variable`` is a variable; anything else (a quoted literal, a bracketed option)
    is a literal. Nothing here is mapped onto the vocabulary: :func:`_map_statement` still does that,
    without handles, exactly as before."""
    operands: list[Operand] = []
    for token in tokens:
        if token.startswith("%"):
            name, _, rest = token.partition("/")
            if rest.strip("/").strip():
                operands.append(Operand("path", "/" + rest, name))
            else:
                operands.append(Operand("handle", name, name))
        elif token.startswith("$"):
            operands.append(Operand("variable", token))
        else:
            operands.append(Operand("literal", token))
    return tuple(operands)


# Verbs that name a whole message handle only to READ it. Deliberately small: a verb missing from it
# makes a handle it names unknown afterwards, which costs a raise at a later send of that handle; a
# verb wrongly in it lets a handle keep a local after Corepoint replaced its content, which costs a
# delivery of the wrong message.
_READ_ONLY_VERBS = frozenset({"msgsend", "msglog"})


def _written_path(action: Action) -> str:
    """The HL7 path a write helper writes: ``copy_field(src, dst)`` its LAST, every other its first."""
    if not action.args:
        return ""
    value = json.loads(action.args[-1] if action.vocabulary == "copy_field" else action.args[0])
    return value if isinstance(value, str) else ""


def _clone_target(deferred: _Deferred) -> str:
    """The destination handle of a ``MsgTreeCopy`` this module reads as a plain whole-tree copy, or
    ``""``.

    The shape is exact: two operands, a whole-tree destination, no qualifier, and no connective but
    ``to``. A mode flag (``merge``, ``append``), a ``from`` that reverses the direction, or a third
    operand means the copy is not a plain one, so the statement falls to the fail-closed rule below."""
    if deferred.verb.lower() != "msgtreecopy" or len(deferred.operands) != 2 or deferred.qualified:
        return ""
    if not {w.lower() for w in deferred.words} <= {"to"}:
        return ""
    return _whole_tree(deferred.operands[1])


def _whole_written(deferred: _Deferred) -> frozenset[str]:
    """The handles a statement may overwrite as a WHOLE tree, judged from the statement alone.

    A plain clone overwrites only its destination, and a read-only verb overwrites nothing. Every
    other statement may overwrite every handle it names whole, in either reading of its markup,
    because nothing this module reads says which operand it writes. That is fail-closed: a handle
    wrongly unbound costs a raise at a later send, a handle wrongly kept costs a wrong delivery. A
    field write (a path into a handle) is not here: it changes part of a tree the local still holds."""
    if deferred.verb.lower() in _READ_ONLY_VERBS:
        return frozenset()
    target = _clone_target(deferred)
    return frozenset({target}) if target else deferred.named


# The message-type and version shapes a ``MsgCreate`` must name to build a valid MSH. Only the caret
# form of the type is read: ``ADT_A01`` is also how HL7 spells a message STRUCTURE (MSH-9.3), so
# splitting an underscore would guess which of the two the export meant.
_MESSAGE_TYPE = re.compile(r"^([A-Z0-9]{3})\^([A-Z0-9]{3})(?:\^([A-Z0-9_]{3,7}))?$")
_HL7_VERSION = re.compile(r"^2\.[1-9](?:\.[1-9])?$")
# The only words a ``MsgCreate`` may carry besides its verb and operands, styled as a keyword or not
# (see :func:`_statement_words`). Anything else (``merging input``) may change what
# is built, and the skeleton would silently drop it.
_MSGCREATE_CONNECTIVES = frozenset({"as", "version"})


def _create_skeleton(deferred: _Deferred) -> tuple[str, str]:
    """``(skeleton, "")`` for a ``MsgCreate``, or ``("", why)`` when no valid MSH can be built.

    The skeleton carries the default encoding characters, the message type in MSH-9 and the version in
    MSH-12, and nothing else. Every other header field is whatever the action-list itself writes. It
    is built through :class:`Message` and encoded, never assembled by string slicing. The export must
    name exactly one message type and one version and nothing else beside the handle, because a
    ``MsgCreate`` naming a template, a variable or a model this module cannot read builds a message
    whose header the skeleton would silently omit."""
    if deferred.qualified:
        return "", "the statement carries a qualifier this import does not read"
    if not {w.lower() for w in deferred.words} <= _MSGCREATE_CONNECTIVES:
        return (
            "",
            "the statement carries a word this import does not read, which may change the build",
        )
    types: list[re.Match[str]] = []
    versions: list[str] = []
    for operand in deferred.operands[1:]:
        if operand.kind not in ("literal", "numeral"):
            return "", "it names something other than an HL7 message type and version"
        if (found := _MESSAGE_TYPE.fullmatch(operand.text)) is not None:
            types.append(found)
        elif _HL7_VERSION.fullmatch(operand.text):
            versions.append(operand.text)
        else:
            return "", "it names something other than an HL7 message type and version"
    if len(types) != 1 or len(versions) != 1:
        return "", (
            "it does not name exactly one HL7 message type (such as ADT^A01) and one HL7 version "
            "(such as 2.5), so no valid MSH can be built"
        )
    try:
        skeleton = Message.parse("MSH|^~\\&|")
        for index, part in enumerate(types[0].groups(), start=1):
            if part is not None:
                skeleton.set(f"MSH-9.{index}", part)
        skeleton.set("MSH-12", versions[0])
    except ValueError as exc:  # HL7PeekError included: a refusal, never a traceback
        return "", f"the MSH could not be built ({type(exc).__name__})"
    return skeleton.encode().rstrip("\r"), ""


class _Env(Mapping[str, str]):
    """Which local each handle holds at the current point of the walk, with an undo journal.

    A construct's arms each start from the same state. Copying the whole map for every arm costs the
    number of bound handles per construct, which an untrusted export can make quadratic. Instead each
    arm runs in place, reports the handles it touched, and is undone, so the cost of an arm is the
    number of handles it actually changes."""

    def __init__(self, initial: dict[str, str]) -> None:
        self._live = dict(initial)
        self._journal: list[tuple[str, str | None]] = []

    def __getitem__(self, handle: str) -> str:
        return self._live[handle]

    def __iter__(self) -> Iterator[str]:
        return iter(self._live)

    def __len__(self) -> int:
        return len(self._live)

    def bind(self, handle: str, local: str) -> None:
        self._journal.append((handle, self._live.get(handle)))
        self._live[handle] = local

    def unbind(self, handle: str) -> None:
        if handle in self._live:
            self._journal.append((handle, self._live.pop(handle)))

    def mark(self) -> int:
        return len(self._journal)

    def changes(self, mark: int) -> dict[str, str | None]:
        """Each handle touched since ``mark``, with the local it holds now (``None``: unbound)."""
        return {handle: self._live.get(handle) for handle, _ in self._journal[mark:]}

    def undo(self, mark: int) -> None:
        while len(self._journal) > mark:
            handle, previous = self._journal.pop()
            if previous is None:
                self._live.pop(handle, None)
            else:
                self._live[handle] = previous

    def narrow(self, outcomes: list[dict[str, str | None]]) -> None:
        """Unbind every handle some path left on a different local than it holds here.

        Each outcome is a :meth:`changes` of a path that began at this state. A handle bound on some
        paths only, or overwritten on any, is unknown after they meet. A handle each path binds afresh
        is unknown too: the conditions are dead placeholders until a human writes them, so no path is
        known to run."""
        for outcome in outcomes:
            for handle, local in outcome.items():
                if self._live.get(handle) != local:
                    self.unbind(handle)


#: In a set of handle keys: the statement may reach ANY handle (a call whose list is not inlined).
_EVERY_HANDLE = "\x00every"
_NAME_WORD = re.compile(r"[A-Za-z0-9_]+")
_HANDLE_WORD = re.compile(r"%([A-Za-z0-9_]+)")


def _handle_key(handle: str) -> str:
    """A handle's name for matching by name: no ``%``, case-folded."""
    return handle.lstrip("%").lower()


def _hit(keys: frozenset[str], handle: str) -> bool:
    """Whether a set of handle keys (see :meth:`_Flow._written`) reaches ``handle``."""
    return _EVERY_HANDLE in keys or _handle_key(handle) in keys


def _forget(env: _Env, deferred: _Deferred) -> None:
    """Unbind every handle the statement may overwrite whole (see :func:`_whole_written`)."""
    for handle in _whole_written(deferred):
        env.unbind(handle)


class _Flow:
    """Settle one handler's step tree in statement order, binding each message handle to a local.

    The input handle is ``msg``. A ``MsgTreeCopy`` of a bound handle's whole tree binds its
    destination to ``<local> = <source>.copy()``, and a ``MsgCreate`` naming a type and a version
    binds its handle to ``<local> = Message.parse(<skeleton>)``. A field write maps onto the local of
    the handle it addresses, and a ``MsgSend`` of a bound handle delivers that local. Anything this
    cannot settle keeps the step 1 refusal: a TODO marker, and at a send or a ``MsgCreate`` a raise.
    Nothing ever falls back to sending ``msg`` (BACKLOG #313, step 2).

    The walk follows the rendered tree, so it sees exactly the order and nesting the generated Python
    runs in. Each local name is fixed per handle for the whole handler, so a handle bound again inside
    a branch rebinds the same Python variable and the join stays faithful.

    The export is untrusted, so the work stays near-linear in the size of the tree: :meth:`_written`
    is memoized per body, each arm runs in place on an :class:`_Env` and is undone, and :meth:`_local`
    resumes each name's counter instead of probing from 2."""

    def __init__(self, input_handle: str, marked: bool = True) -> None:
        self._input = input_handle
        self._marked = marked
        # Locals a MsgCreate built: their skeleton holds only an MSH.
        self._created: set[str] = set()
        self._names: dict[str, str] = {}
        self._taken: set[str] = {"msg", "sends", "_item"}
        self._next: dict[str, int] = {}
        # Keyed by the id of a body tuple of the unsettled tree. The tuple rides in the value, so it
        # stays alive and its id cannot be reused for another body while this walk runs.
        self._written_memo: dict[int, tuple[tuple[Step, ...], frozenset[str]]] = {}
        self._text_memo: dict[int, tuple[tuple[Step, ...], frozenset[str]]] = {}

    def handler(self, steps: tuple[Step, ...]) -> tuple[Step, ...]:
        env = _Env({self._input: "msg"} if self._input else {})
        return tuple(self._run_in_line(steps, env))

    def _run_in_line(self, steps: tuple[Step, ...], env: _Env) -> list[Step]:
        """Settle ``steps`` in line, leaving ``env`` at what holds after them."""
        return [self._step(step, env) for step in steps]

    def _arm(self, steps: tuple[Step, ...], env: _Env) -> tuple[list[Step], dict[str, str | None]]:
        """Settle one path from the current state, then restore it; return the path's changes."""
        mark = env.mark()
        settled = self._run_in_line(steps, env)
        changes = env.changes(mark)
        env.undo(mark)
        return settled, changes

    def _written(self, steps: tuple[Step, ...]) -> frozenset[str]:
        """The keys (see :func:`_hit`) of every handle any live statement in ``steps`` may overwrite
        whole, nested constructs included; :data:`_EVERY_HANDLE` when that may be any handle.

        Read on the UNSETTLED tree, so it is a syntactic answer: a clone this walk will bind counts as
        a write as surely as an overwrite it cannot model. A loop and a ``Try`` use it to say which
        handles may differ on a later pass or in a ``Catch``. Memoized, so nested loops and ``Try``
        blocks share one pass over each body rather than walking it again at every level."""
        cached = self._written_memo.get(id(steps))
        if cached is not None:
            return cached[1]
        found: set[str] = set()
        for step in steps:
            if not isinstance(step, Control) or step.kind == "disabled":
                continue
            if step.deferred is not None and step.kind in ("pending", "unknown"):
                found.update(_handle_key(h) for h in _whole_written(step.deferred))
            if step.kind == "call":
                found |= self._call_keys(step)  # what a call leaves unknown (see _call)
            found |= self._written(step.body)
            for branch in step.branches:
                found |= self._written(branch.body)
        result = frozenset(found)
        self._written_memo[id(steps)] = (steps, result)
        return result

    def _local(self, handle: str) -> str:
        """The Python local for ``handle``: fixed per handler, ASCII, never a keyword or a name the
        generated module already uses (every one ends ``_msg``, which none of those does)."""
        name = self._names.get(handle)
        if name is not None:
            return name
        base = re.sub(r"[^a-z0-9]+", "_", handle.lower()).strip("_")[:40].rstrip("_")
        if not base or not base[0].isalpha():
            base = f"tree_{base}".rstrip("_")
        n = self._next.get(base, 1)
        name = f"{base}_msg" if n == 1 else f"{base}_msg_{n}"
        while name in self._taken:
            n += 1
            name = f"{base}_msg_{n}"
        self._next[base] = n + 1
        self._taken.add(name)
        self._names[handle] = name
        return name

    def _step(self, step: Step, env: _Env) -> Step:
        """Settle one step, leaving ``env`` at what holds after it."""
        if not isinstance(step, Control):
            return step
        kind = step.kind
        if kind == "disabled":
            # Settled for the comment block only: it never ran, so nothing it binds leaks out.
            body, _ = self._arm(step.body, env)
            return replace(step, body=tuple(body))
        if kind == "pending":
            assert step.deferred is not None
            return self._statement(step, step.deferred, env)
        if kind == "send":
            return self._send(step, env)
        if kind == "block":
            # A section label: its body runs in line.
            settled = replace(step, body=tuple(self._run_in_line(step.body, env)))
        elif kind == "call":
            settled = self._call(step, env)
        elif kind in _LOOP_KINDS:
            # A later pass may start from what an earlier one overwrote, so a handle the body may
            # overwrite is unknown throughout it, and after it (the body may run no times at all).
            written = self._written(step.body)
            for handle in list(env):
                if _hit(written, handle):
                    env.unbind(handle)
            body, _ = self._arm(step.body, env)
            settled = replace(step, body=tuple(body))
        elif kind == "try":
            settled = self._try(step, env)
        elif kind in ("if", "case"):
            if kind == "case":
                # A ChooseFrom's statements before its first arm run unconditionally, in line.
                body = self._run_in_line(step.body, env)
                outcomes = []
            else:
                body, first = self._arm(step.body, env)
                outcomes = [first]
            branches: list[Control] = []
            for branch in step.branches:
                arm, changes = self._arm(branch.body, env)
                outcomes.append(changes)
                branches.append(replace(branch, body=tuple(arm)))
            env.narrow(outcomes)
            settled = replace(step, body=tuple(body), branches=tuple(branches))
        else:
            # "unknown", an orphaned branch marker, "break", "exit": the body is inlined in place
            # but its own scope was lost, so nothing it binds is trusted after it.
            if kind == "unknown" and step.deferred is not None:
                _forget(env, step.deferred)
            body, changes = self._arm(step.body, env)
            env.narrow([changes])
            settled = replace(step, body=tuple(body))
        return self._strays(settled, env)

    def _try(self, step: Control, env: _Env) -> Control:
        """Settle a ``Try``: its body, then each ``Catch`` from what the body cannot have changed."""
        catches = [b for b in step.branches if _renders_as_branch(step.kind, b.kind)]
        if not catches:
            # No Catch renders as ``except Exception: raise``, so the code after the Try runs only
            # when the body completed, and the body's state is exactly what holds there.
            body = self._run_in_line(step.body, env)
            return replace(step, body=tuple(body))
        body, body_changes = self._arm(step.body, env)
        outcomes = [body_changes]
        # A Catch may start anywhere in the body, so what the body may overwrite is unknown there.
        mark = env.mark()
        written = self._written(step.body)
        for handle in list(env):
            if _hit(written, handle):
                env.unbind(handle)
        settled_catches: dict[int, Control] = {}
        for branch in catches:
            start = env.mark()
            arm = self._run_in_line(branch.body, env)
            outcomes.append(env.changes(mark))  # from the Try's start: the unbinds and this Catch
            env.undo(start)
            settled_catches[id(branch)] = replace(branch, body=tuple(arm))
        env.undo(mark)
        env.narrow(outcomes)
        # A stray stays as it is here; :meth:`_strays` settles it where the render puts it.
        branches = tuple(settled_catches.get(id(b), b) for b in step.branches)
        return replace(step, body=tuple(body), branches=branches)

    def _call(self, step: Control, env: _Env) -> Control:
        """Settle an ``ActionListCall``: the called list runs in its OWN scope.

        Nothing ties the handle names inside a called list to the caller's: it may name the message
        it was passed by its own input handle, or reuse a caller's name for a different tree. So the
        inlined body starts knowing no handle at all. Afterwards the caller can vouch for no handle
        the call might reach, judged by NAME on the raw text, case-insensitively, so no pass syntax
        or span class can hide one (see :meth:`_call_keys`). Fail closed: a later send of one of
        those raises."""
        keys = self._call_keys(step)
        body = self._run_in_line(step.body, _Env({}))
        for handle in list(env):
            if _hit(keys, handle):
                env.unbind(handle)
        return replace(step, body=tuple(body))

    def _call_keys(self, step: Control) -> frozenset[str]:
        """The handle keys a call may reach: every word of its call line (a pass may be spelled any
        way), and every ``%`` handle named anywhere in its inlined list. A call whose list is not
        inlined may reach any handle at all."""
        if not step.body:
            return frozenset({_EVERY_HANDLE})
        return frozenset(w.lower() for w in _NAME_WORD.findall(step.detail)) | self._text_keys(
            step.body
        )

    def _text_keys(self, steps: tuple[Step, ...]) -> frozenset[str]:
        """Every ``%`` handle key named in the raw text of any live statement in ``steps``.

        Read from the statement text rather than from parsed operands, so a span class the role
        layer does not list, an unknown tag, or a path operand cannot hide a handle. Memoized."""
        cached = self._text_memo.get(id(steps))
        if cached is not None:
            return cached[1]
        found: set[str] = set()
        for step in steps:
            if not isinstance(step, Control) or step.kind == "disabled":
                continue
            found.update(w.lower() for w in _HANDLE_WORD.findall(step.detail))
            found |= self._text_keys(step.body)
            for branch in step.branches:
                found |= self._text_keys(branch.body)
        result = frozenset(found)
        self._text_memo[id(steps)] = (steps, result)
        return result

    def _strays(self, ctrl: Control, env: _Env) -> Control:
        """Settle the branches the render inlines AFTER ``ctrl`` (see :func:`_stray_branches`)."""
        if all(_renders_as_branch(ctrl.kind, branch.kind) for branch in ctrl.branches):
            return ctrl
        branches: list[Control] = []
        for branch in ctrl.branches:
            if _renders_as_branch(ctrl.kind, branch.kind):
                branches.append(branch)
                continue
            arm, changes = self._arm(branch.body, env)
            env.narrow([changes])
            branches.append(replace(branch, body=tuple(arm)))
        return replace(ctrl, branches=tuple(branches))

    def _send(self, step: Control, env: _Env) -> Control:
        """A send of a bound handle delivers its local; anything else raises at the send site."""
        assert step.deferred is not None  # the parse gives every send its operands
        operands = step.deferred.operands
        sent = _whole_tree(operands[0]) if operands else ""
        refusal = _send_refusal(sent, env)
        if refusal:
            return replace(step, refusal=refusal)
        return replace(step, message=env[sent])

    def _statement(self, step: Control, deferred: _Deferred, env: _Env) -> Step:
        """Settle one transform statement: a field write, a clone, a ``MsgCreate``, or a marker."""
        verb, operands = deferred.verb, deferred.operands
        if deferred.flat is not None:
            result = self._flat_write(deferred.flat, deferred, env)
        elif _clone_target(deferred):
            return self._tree_copy(step, operands, env)
        elif verb.lower() == "msgcreate" and operands and _whole_tree(operands[0]):
            return self._create(step, deferred, env)
        else:
            mapped = _map_roles(
                verb,
                operands,
                env,
                # An unstyled verb is not read as a word for clones (see _statement_words), but a field
                # write keeps declining on it, as it always did: whether that is safe was never decided.
                words=deferred.words if deferred.styled else (verb, *deferred.words),
                qualified=deferred.qualified,
                in_control=deferred.in_control,
            )
            result = mapped if mapped is not None else _decline(verb, operands, env)
        _forget(env, deferred)
        return self._skeleton_guard(result)

    def _skeleton_guard(self, result: Step) -> Step:
        """Decline a write a ``MsgCreate`` skeleton cannot take.

        The skeleton holds only an MSH, and :meth:`Message.set` raises on an absent segment, so a
        mapped write to any other segment of a built message would dead-letter every message, or be
        swallowed by a ``Catch``. It becomes a TODO instead: the segment has to be added by hand. A
        write to MSH-1/MSH-2 is refused as everywhere else (see :func:`_writable`)."""
        if not isinstance(result, Action) or result.target not in self._created:
            return result
        path = _written_path(result)
        if (
            result.vocabulary in ("set_field", "append_to_field")
            and _writable(path)
            and path.split("-", 1)[0].upper() == "MSH"
        ):
            return result
        return UnmappedAction(
            result.source_class,
            f"writes a message MsgCreate built, whose skeleton has only an MSH segment, so the "
            f"segment this write needs must be added by hand; intended target {path}",
        )

    def _flat_write(
        self, flat: Action | UnmappedAction, deferred: _Deferred, env: _Env
    ) -> Action | UnmappedAction:
        """Point a markup-free write at the local of the one handle its paths address.

        A list with no role markup at all keeps the superseded model's reading: its writes land on
        ``msg``. In any list with role markup, a markup-free write must not land on ``msg`` by
        default: it lands on the local of the one handle it addresses, or declines. It also maps
        only as the role layer would map it: never ``copy_field``, which clears the destination when
        the source is absent, never a repeating segment, never MSH-1/MSH-2."""
        if not isinstance(flat, Action):
            return flat
        if not self._marked:
            # MSH-1/MSH-2 corrupt the framing whichever model reads the list (see _FRAMING_PATHS).
            if _written_path(flat) in _FRAMING_PATHS:
                return UnmappedAction(
                    flat.source_class,
                    f"targets {_written_path(flat)}, a framing field this import never writes",
                )
            return flat
        if deferred.in_control:
            return UnmappedAction(
                flat.source_class,
                "a markup-free write inside a branch or loop declines, as a role-parsed one does; "
                f"intended target {_written_path(flat)}",
            )
        target = _written_path(flat)
        if flat.vocabulary not in ("set_field", "append_to_field") or not _writable(target):
            return UnmappedAction(
                flat.source_class,
                "a markup-free write in a list with role markup maps only as the role layer would "
                "(no copy_field, no repeating segment, no MSH-1/MSH-2); "
                f"intended target {target}",
            )
        handles = {o.handle for o in deferred.operands if o.kind == "path"}
        handle = next(iter(handles)) if len(handles) == 1 else ""
        if handle in env:
            return replace(flat, target=env[handle])
        return UnmappedAction(
            flat.source_class,
            "a markup-free write that addresses a message handle that holds no message this "
            f"import can identify at this point (cross-message); intended target {target}",
        )

    def _tree_copy(self, step: Control, operands: tuple[Operand, ...], env: _Env) -> Step:
        source, dest = _whole_tree(operands[0]), _whole_tree(operands[1])
        verb = step.source_verb
        if dest == self._input:
            # Rebinding msg would leave every later write and send of the input addressing a
            # different object than the one that arrived. Unknown from here on instead.
            env.unbind(dest)
            return UnmappedAction(
                verb,
                "overwrites the input handle; msg stays the message that arrived, so the input is "
                "unknown from here on",
            )
        if source and source in env:
            expression = f"{env[source]}.copy()"
            local = self._local(dest)
            env.bind(dest, local)
            if env[source] in self._created:
                self._created.add(local)  # a copy of a skeleton is still only a skeleton
            return Control("clone", verb, step.detail, args=(local, expression))
        env.unbind(dest)
        what = (
            f"{_comment_text(source, 60)}, which holds no message this import can identify here"
            if source
            else "something that is not a whole message tree"
        )
        return UnmappedAction(
            verb, f"copies {what} over {_comment_text(dest, 60)}, which is unknown from here on"
        )

    def _create(self, step: Control, deferred: _Deferred, env: _Env) -> Step:
        handle = _whole_tree(deferred.operands[0])
        _forget(env, deferred)  # every handle it names, not only the one it builds
        name = _comment_text(handle, 60)
        if handle == self._input:
            why = "a new message in the input handle would replace msg, the message that arrived"
        else:
            skeleton, why = _create_skeleton(deferred)
            if not why:
                local = self._local(handle)
                env.bind(handle, local)
                self._created.add(local)
                return Control(
                    "create",
                    step.source_verb,
                    step.detail,
                    args=(local, f"Message.parse({_lit(skeleton)})"),
                )
        return Control(
            "create",
            step.source_verb,
            step.detail,
            refusal=f"{name} is not built: {why}; the import refuses to guess the message",
        )


def _hardened_fromstring(text: str) -> Element:
    """THE XML parse surface of this module — ``defusedxml`` with every hardening flag ON.

    ``forbid_dtd`` / ``forbid_entities`` / ``forbid_external`` are all set, the same posture as
    :meth:`RawMessage.xml` and ``transports.soap._assert_well_formed_fragment`` (ASVS 1.5.3): a
    billion-laughs, an internal DTD, or an external-entity (``file://`` / ``http://``) payload
    **raises** rather than expanding or fetching. Isolated in one function so the parser-consistency
    corpus (``tests/test_xml_parser_consistency.py``) can drive this surface directly — a hostile
    document must be refused *here*, not merely rejected later by a structural check.

    Every failure becomes :class:`CorepointImportError`, because an export is untrusted data and the
    CLI must report it cleanly instead of raising an uncaught traceback."""
    try:
        return _xml_fromstring(  # type: ignore[no-any-return]
            # A Windows-authored export is routinely saved UTF-8-with-BOM, and a BOM decoded into the
            # string is not legal *before* the XML declaration — drop it rather than reject the file.
            text.lstrip("﻿"),
            forbid_dtd=True,
            forbid_entities=True,
            forbid_external=True,
        )
    except ParseError as exc:
        raise CorepointImportError(f"export is not well-formed XML: {exc}") from exc
    except DefusedXmlException as exc:
        raise CorepointImportError(f"export carries a forbidden XML construct: {exc}") from exc


def parse_package(text: str, *, source_name: str = "package") -> tuple[Channel, ...]:
    """Parse a real Corepoint ``<Package>`` XML export into the intermediate channel model.

    One :class:`Channel` per package: every ``<ActionList>`` in the document becomes a
    :class:`Handler`, and the destinations are whatever the ``MsgSend`` statements name. The package's
    connection subtrees are **not** modelled, so the emitted endpoints are inert ``deployed=False``
    placeholders to hand-finish (see the module docstring).

    Hardened + defensive: the parse runs through ``defusedxml`` with ``forbid_dtd`` /
    ``forbid_entities`` / ``forbid_external`` all ON, so a billion-laughs or external-entity payload
    raises :class:`CorepointImportError` instead of expanding; malformed XML and a package with no
    ``<ActionList>`` do the same."""
    root = _hardened_fromstring(text)

    lists = [e for e in root.iter() if _local(e.tag).lower() == "actionlist"]
    if not lists:
        raise CorepointImportError(
            f"export root <{_local(root.tag)}> carries no <ActionList> to import"
        )

    package = _attr(root, "Name") or source_name
    ident = _sanitize(package)
    module_name = _connection_name(f"IB_{ident.upper()}")

    # ElementTree carries no parent link, so build one pass of child→parent up front: an <ActionList>
    # is switched off by @Disabled on ITSELF or on any element enclosing it (typically <Package>).
    parents = {child: parent for parent in root.iter() for child in parent}

    handlers: list[Handler] = []
    taken: set[str] = {"route"}
    destinations: list[str] = []
    for i, action_list in enumerate(lists):
        raw_name = _attr(action_list, "Name") or f"transform_{i + 1}"
        # Lower-case BEFORE sanitizing so the keyword guard sees the final identifier ("Class" →
        # "class" → "class_"): the name is both the ``@handler`` id and the emitted ``def``.
        name = _sanitize(raw_name.lower())
        if name in taken:
            n = 2
            while f"{name}_{n}" in taken:
                n += 1
            name = f"{name}_{n}"
        taken.add(name)
        # Parse the whole tree first, then settle it in statement order: which message a handle holds
        # depends on what ran before it, and only the parsed tree knows the branch structure.
        parsed = tuple(_container_steps(action_list, False))
        steps = _Flow(*_input_handle(action_list)).handler(parsed)
        scope = _disabled_scope(action_list, parents)
        if scope is not None:
            # The whole list is switched off: wrap it in ONE disabled node so it is preserved as
            # commented-out pseudo-source, counted as disabled, and — because _collect_sends skips a
            # disabled subtree — names no destination and gets no live trailing Send.
            tag, label = scope
            steps = (Control("disabled", tag, label or raw_name, body=steps),)
        sends = _collect_sends(steps)
        for dest in sends:
            if dest not in destinations:
                destinations.append(dest)
        handlers.append(Handler(name, steps, sends, disabled=scope is not None))

    # The package's connection subtrees are unmodelled, so wiring is a placeholder: a File endpoint
    # needs no port (it can never collide with a real one) and ``deployed=False`` binds nothing at all.
    rendered = tuple(
        Destination(d, "File", f"File(directory={_lit(_placeholder_dir(module_name, d))})")
        for d in destinations
    )
    inbound_call = f"File(directory={_lit(_placeholder_dir(module_name, 'in'))})"
    return (
        Channel(
            module_name,
            "File",
            inbound_call,
            f"{ident.lower()}_router",
            rendered,
            tuple(handlers),
            source_format="xml",
        ),
    )


def _placeholder_dir(module_name: str, leaf: str) -> str:
    """The inert directory a placeholder endpoint points at (it is never deployed, so never polled)."""
    return f"./corepoint-import/{module_name}/{leaf}"


def _collect_sends(steps: tuple[Step, ...]) -> tuple[str, ...]:
    """Every destination name a **live** ``MsgSend`` names, in first-seen order (deduped), depth-first.

    A ``@Disabled`` subtree is skipped, and that skip is load-bearing rather than cosmetic: these names
    become the handler's ``destinations``, and a handler with destinations but no *inline* send falls
    back to emitting a trailing ``return Send(...)``. Walking into a disabled subtree would therefore
    resurrect a switched-off send as live code — the one thing ``@Disabled`` must never do.

    It walks exactly what the render emits: each step's body and each branch's BODY. A branch's own
    ``branches`` (a marker nested inside a branch) is not rendered, so a send there must not be
    collected either, or it would come back as a trailing ``Send(dest, msg)``: the fallback to msg
    BACKLOG #313 removed, made unconditional (the nested-branch drop itself is a separate defect)."""
    found: list[str] = []
    for step in steps:
        if not isinstance(step, Control) or step.kind == "disabled":
            continue
        if step.kind == "send" and step.args:
            name = json.loads(step.args[0])
            if name not in found:
                found.append(name)
        nested_bodies = (step.body, *(branch.body for branch in step.branches))
        for nested in (name for body in nested_bodies for name in _collect_sends(body)):
            if nested not in found:
                found.append(nested)
    return tuple(found)


def parse_any(text: str, *, source_name: str = "package") -> tuple[Channel, ...]:
    """Parse either export shape: a leading ``<`` selects the validated XML layer, else the JSON one."""
    if text.lstrip("﻿ \t\r\n").startswith("<"):  # a leading BOM must not defeat the sniff
        return parse_package(text, source_name=source_name)
    return parse_export(text)


# --- code generation ---------------------------------------------------------


def generate_module(channel: Channel) -> str:
    """Emit a complete, importable ``@router``/``@handler`` config module for ``channel``.

    The output calls the ADR 0076 vocabulary + :class:`Send` and is designed to pass ``messagefoundry
    check`` and round-trip through ``lens parse`` (every mapped step classifies into a typed action
    row; a TODO marker is a bare comment and so contributes no row at all — never a whole-file
    refusal)."""
    used_vocab: set[str] = set()
    used_connectors: set[str] = {channel.inbound_connector}
    for d in channel.destinations:
        used_connectors.add(d.connector)
    for h in channel.handlers:
        used_vocab.update(_vocabulary_used(h.steps))

    xml = channel.source_format == "xml"
    provenance = (
        [
            "Mechanically translated from a Corepoint `<Package>` XML export — the VALIDATED schema",
            "(ADR 0086 §2 as amended). The package's connection subtrees are not modelled, so the",
            "endpoints below are inert `deployed=False` placeholders: wire the real transports, then",
            "verify every field path and every `# TODO: Corepoint ...` hand-finish marker.",
        ]
        if xml
        else [
            "This module was mechanically translated from a SYNTHETIC-schema Corepoint export (the",
            "superseded JSON model, ADR 0086 §2(a)); the validated input is the XML `<Package>` shape.",
            "Verify field paths, routing, and any `# TODO: Corepoint ...` markers before deploying.",
        ]
    )
    lines: list[str] = [
        "# SPDX-License-Identifier: AGPL-3.0-or-later",
        "# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors",
        '"""Generated by `messagefoundry import corepoint` (ADR 0086) — REVIEW before production use.',
        "",
        *provenance,
        '"""',
        "",
    ]

    surface = ["Send", "handler", "inbound", "outbound", "router"]
    if any(_any_live_control(h.steps, _builds_a_message) for h in channel.handlers):
        surface.append("Message")  # a MsgCreate binds its handle to Message.parse(...)
    surface_imports = sorted({*surface, *used_connectors})
    lines.append(f"from messagefoundry import {', '.join(surface_imports)}")
    if used_vocab:
        lines.append(f"from messagefoundry.actions import {', '.join(sorted(used_vocab))}")
    lines.append("")

    # Endpoints: inbound (naming its router) + one outbound per destination. An XML-sourced channel
    # emits them ``deployed=False`` (#233, ADR 0111) — present in the config, binding nothing — because
    # the transports are placeholders, so an unfinished import can never open a socket or poll a path.
    placeholder = ", deployed=False" if xml else ""
    if xml:
        lines.append(
            "# TODO: Corepoint — the export's connection config is not modelled; these endpoints are"
        )
        lines.append(
            "# placeholders. Replace them with the real transports, then drop deployed=False."
        )
    lines.append(
        f"inbound({_lit(channel.module_name)}, {channel.inbound_call}, "
        f"router={_lit(channel.router_name)}{placeholder})"
    )
    for d in channel.destinations:
        lines.append(f"outbound({_lit(d.name)}, {d.call}{placeholder})")
    lines.append("")
    lines.append("")

    # Router: forwards to every LIVE handler (Corepoint routing is per-channel; refine by hand). A
    # handler whose whole <ActionList> carried @Disabled is deliberately NOT forwarded to — routing to it
    # would run a list the operator switched off — but it is named in a comment, never silently missing.
    handler_names = [h.name for h in channel.handlers if not h.disabled]
    switched_off = [h.name for h in channel.handlers if h.disabled]
    lines.append(f"@router({_lit(channel.router_name)})")
    lines.append("def route(msg):  # type: ignore[no-untyped-def]")
    if switched_off:
        lines.append(
            f"    # DISABLED in Corepoint (@Disabled) — NOT routed: {', '.join(switched_off)}"
        )
    rendered_names = ", ".join(_lit(n) for n in handler_names)
    lines.append(
        f"    return [{rendered_names}]  # TODO: Corepoint routing — forwards to all handlers"
    )
    lines.append("")
    lines.append("")

    for hi, h in enumerate(channel.handlers):
        lines.extend(_generate_handler(h))
        if hi != len(channel.handlers) - 1:
            lines.append("")
            lines.append("")

    return "\n".join(lines) + "\n"


# The body of a handler whose whole <ActionList> is @Disabled: it filters, and says why.
_DISABLED_RETURN = (
    "    return None  # DISABLED in Corepoint (@Disabled) — this action-list never ran; "
    "review above before enabling"
)


def _generate_handler(h: Handler) -> list[str]:
    lines = [f"@handler({_lit(h.name)})", f"def {h.name}(msg):  # type: ignore[no-untyped-def]"]
    if h.disabled:
        # The whole action-list carried @Disabled. The def stays — so the switched-off list is visible
        # to whoever finishes the wiring — but its every statement is commented-out pseudo-source, it
        # names no destination, and the router above does not forward to it. Nothing here is live.
        return [*lines, *_generate_steps(h.steps, 1, in_loop=False), _DISABLED_RETURN]
    body: list[str] = []
    # A ``MsgSend`` can sit inside a branch, so an inline-send handler accumulates its Sends where the
    # export put them and returns the list — flattening them to a single trailing Send would silently
    # turn a conditional send into an unconditional one.
    inline_sends = _has_inline_send(h.steps)
    if inline_sends:
        body.append("    sends = []")
    body.extend(_generate_steps(h.steps, 1, in_loop=False))

    # Return the Sends. A handler with no destination filters (returns None); one destination returns a
    # single Send; several return a list of Sends.
    if inline_sends:
        body.append("    return sends")
    elif not h.destinations:
        body.append(
            "    return None  # TODO: Corepoint export named no destination for this handler"
        )
    elif len(h.destinations) == 1:
        body.append(f"    return Send({_lit(h.destinations[0])}, msg)")
    else:
        sends = ", ".join(f"Send({_lit(d)}, msg)" for d in h.destinations)
        body.append(f"    return [{sends}]")
    lines.extend(body)
    return lines


def _generate_steps(steps: tuple[Step, ...], indent: int, *, in_loop: bool) -> list[str]:
    """Render a step tree to source lines at ``indent`` levels of four spaces."""
    pad = "    " * indent
    out: list[str] = []
    for step in steps:
        if isinstance(step, Action):
            parts = [f"{step.target}, {', '.join(step.args)}"] if step.args else [step.target]
            for kw_name, kw_val in step.keywords:
                parts.append(f"{kw_name}={kw_val}")
            out.append(f"{pad}{step.vocabulary}({', '.join(parts)})")
        elif isinstance(step, UnmappedAction):
            # A marker and nothing else. Both fields arrive RAW — on the JSON layer ``source_class``
            # is an arbitrary export string and ``detail`` quotes one — so this render site is where
            # they are escaped for the comment they are about to become (#1683).
            out.append(
                f"{pad}# TODO: Corepoint {_comment_text(step.source_class, 60)} — hand-finish "
                f"({_comment_text(step.detail)})"
            )
        else:
            out.extend(_generate_control(step, indent, in_loop=in_loop))
    return out


def _generate_control(ctrl: Control, indent: int, *, in_loop: bool) -> list[str]:
    """Render one control construct, then whatever branches it could not continue.

    The tail runs for EVERY kind, so a construct added later cannot silently drop an adopted branch by
    forgetting to ask for it — see :func:`_stray_branches` (BACKLOG #1854)."""
    out = _generate_construct(ctrl, indent, in_loop=in_loop)
    out.extend(_stray_branches(ctrl, indent, in_loop=in_loop))
    return out


def _generate_construct(ctrl: Control, indent: int, *, in_loop: bool) -> list[str]:
    """Render the construct itself. Conditions are never guessed — they become dead placeholders."""
    pad = "    " * indent
    label = _comment_text(ctrl.detail)
    suffix = f" — hand-finish: {label}" if label else ""

    if ctrl.kind == "disabled":
        return _disabled_lines(ctrl, pad)
    if ctrl.kind in ("block", "call"):
        # A section label / an inlined call: a comment, then the body at the SAME indentation.
        head = f"Corepoint {ctrl.source_verb}"
        if ctrl.kind == "call" and not ctrl.body:
            # Nothing was inlined, so what the called list did is absent: say so, never "inlined".
            return [f"{pad}# TODO: Corepoint {ctrl.source_verb} — called list not inlined{suffix}"]
        if ctrl.kind == "call":
            head += " (called list inlined)"
        out = [f"{pad}# {head}: {label}" if label else f"{pad}# {head}"]
        out.extend(_generate_steps(ctrl.body, indent, in_loop=in_loop))
        return out
    if ctrl.kind == "unknown":
        # An element whose TAG this layer does not model. Its body rides inline under the marker: the
        # element's own scope is lost (it may have been conditional), so the marker says so rather than
        # inventing one — and the subtree is never dropped.
        out = [f"{pad}# TODO: Corepoint <{ctrl.source_verb}> — element not modelled{suffix}"]
        if ctrl.body:
            out.append(
                f"{pad}#   its body is inlined below at THIS indentation — the element's own scope "
                f"is lost, re-scope by hand"
            )
        out.extend(_generate_steps(ctrl.body, indent, in_loop=in_loop))
        return out
    if ctrl.kind == "send":
        if ctrl.refusal:
            # A send of the wrong message. The raise keeps the destination and the ``sends`` list, so
            # the handler neither sends msg here, nor filters silently, nor gains a trailing Send.
            # Reaching this line is a loud ERROR (dead-letter), never a delivery (BACKLOG #313). The
            # outbound stays declared for the hand-finish; ``check`` reports it unreferenced until then,
            # which is accurate: nothing sends to it yet.
            dest = f"to {json.loads(ctrl.args[0])}" if ctrl.args else "(no destination named)"
            message = _lit(f"Corepoint import: {ctrl.source_verb} {dest}: {ctrl.refusal}")
            return [
                f"{pad}# TODO: Corepoint {ctrl.source_verb} {_comment_text(dest)} — hand-finish: "
                f"{_comment_text(ctrl.refusal)} ({label})",
                f"{pad}raise NotImplementedError({message})",
            ]
        if not ctrl.args:
            return [
                f"{pad}# TODO: Corepoint {ctrl.source_verb} — hand-finish: no destination named "
                f"({label})"
            ]
        if not ctrl.message:
            # :class:`_Flow` either binds the local or sets a refusal. Neither happened, which is a
            # defect in this module; guessing ``msg`` here is the exact fallback #313 removed.
            raise CorepointImportError(
                f"internal: a Corepoint {ctrl.source_verb} reached the render with no message"
            )
        return [
            f"{pad}sends.append(Send({ctrl.args[0]}, {ctrl.message}))  # Corepoint {ctrl.source_verb}"
        ]
    if ctrl.kind in _BINDING_KINDS:
        if ctrl.refusal:
            # Reaching this line is a loud ERROR (dead-letter), exactly like a refused send: the
            # handle would otherwise be sent, or written, holding a message nobody built.
            message = _lit(f"Corepoint import: {ctrl.source_verb}: {ctrl.refusal}")
            return [
                f"{pad}# TODO: Corepoint {ctrl.source_verb} — hand-finish: "
                f"{_comment_text(ctrl.refusal)} ({label})",
                f"{pad}raise NotImplementedError({message})",
            ]
        # Both halves are generated: the local is a name _Flow made, the expression a local plus
        # ``.copy()`` or a ``Message.parse`` of a :func:`_lit` literal. No export text reaches here raw.
        local, expression = ctrl.args
        return [f"{pad}{local} = {expression}  # Corepoint {label or ctrl.source_verb}"]
    if ctrl.kind == "pending":
        # :class:`_Flow` settles every one. Reaching the render unsettled is a defect in this module,
        # and emitting nothing here would silently drop the statement.
        raise CorepointImportError(
            f"internal: a Corepoint {ctrl.source_verb} statement reached the render unsettled"
        )
    if ctrl.kind == "break":
        if in_loop:
            return [f"{pad}break  # Corepoint {ctrl.source_verb}"]
        return [f"{pad}# TODO: Corepoint {ctrl.source_verb} outside a loop{_hint(label)}"]
    if ctrl.kind == "exit":
        # ``Returns``/``ActionListExit``/``ActionListStop`` end the list; a bare ``return`` here would
        # silently drop the handler's Sends, so the flow is flagged for a human, never guessed.
        return [f"{pad}# TODO: Corepoint {ctrl.source_verb} (ends this list){suffix}"]
    if ctrl.kind == "try":
        out = [f"{pad}try:"]
        out.extend(_block_body(ctrl.body, indent + 1, in_loop=in_loop))
        # The complement of this filter is what :func:`_stray_branches` marks, so both sides read the
        # same predicate — a ``try`` that learns a new branch kind cannot leave one in neither set.
        handlers = [b for b in ctrl.branches if _renders_as_branch(ctrl.kind, b.kind)]
        if _has_refusal(ctrl.body):
            # Every Catch renders as ``except Exception:``, which would swallow the refusal's raise
            # and run the Catch body instead: a delivery or a silent filter (BACKLOG #313).
            out.append(
                f"{pad}except NotImplementedError:  # a refused Corepoint statement above — "
                "never caught"
            )
            out.append(f"{pad}    raise")
        if not handlers:
            out.append(f"{pad}except Exception:  # TODO: Corepoint Try with no Catch — hand-finish")
            out.append(f"{pad}    raise")
        for branch in handlers:
            out.append(
                f"{pad}except Exception:  # TODO: Corepoint {branch.source_verb}"
                f"{_hint(_comment_text(branch.detail))}"
            )
            out.extend(_block_body(branch.body, indent + 1, in_loop=in_loop))
        return out
    if ctrl.kind == "for":
        out = [f"{pad}for _item in []:  # TODO: Corepoint {ctrl.source_verb}{suffix}"]
        out.extend(_block_body(ctrl.body, indent + 1, in_loop=True))
        return out
    if ctrl.kind == "while":
        out = [f"{pad}while False:  # TODO: Corepoint {ctrl.source_verb}{suffix}"]
        out.extend(_block_body(ctrl.body, indent + 1, in_loop=True))
        return out
    if ctrl.kind in ("if", "case"):
        return _generate_conditional(ctrl, indent, in_loop=in_loop)
    # A branch marker with no construct to continue (a malformed / unexpected placement). Emitting a
    # bare ``else:`` would not even parse, so it degrades to a marker + its body inline — never lost.
    out = [f"{pad}# TODO: Corepoint {ctrl.source_verb} with no enclosing construct{suffix}"]
    out.extend(_generate_steps(ctrl.body, indent, in_loop=in_loop))
    return out


# The kinds whose body the render emits inside a real Python loop. Read by the render and by
# :func:`_count_steps` alike, so the two cannot disagree on where a ``LoopExit`` is live (#1860).
_LOOP_KINDS = frozenset({"for", "while"})


def _renders_as_branch(parent_kind: str, branch_kind: str) -> bool:
    """Whether :func:`_generate_construct` emits this branch as real Python control flow.

    THE single answer, asked by the render and by :func:`_count_steps` alike, because the summary is a
    count-and-log record and a branch the render only marks must not be reported as shipped. An
    ``if``/``case`` chain takes every branch as an arm — a stray marker there is a mislabelled arm,
    not a loss — while a ``try`` speaks only ``except`` and a loop speaks no branch at all.

    Spelled out rather than read off ``_BRANCH_PARENT``: that table says which construct may ADOPT a
    marker, which is a parse question. This is a render question, and the two part company the moment
    a construct adopts a kind it has no faithful form for — a ``finally`` added to the table would
    otherwise be rendered as ``except Exception:``, which is worse than being marked."""
    if parent_kind in ("if", "case"):
        return True
    return parent_kind == "try" and branch_kind == "except"


def _stray_branches(ctrl: Control, indent: int, *, in_loop: bool) -> list[str]:
    """Render the branches ``ctrl`` cannot continue: a TODO marker, then the body inline.

    :func:`_split_branches` adopts ANY bodyless branch marker written inside a container's own
    ``<List>`` without checking that the marker's construct matches that container, so an ``Else``
    lands on a ``Try`` and a ``Catch`` on a ``ForEach``. Keeping only the branches a render understood
    dropped the rest with their whole bodies, while the summary counted every dropped statement as
    mapped — worse than a plain drop, because it asserted the statement shipped (BACKLOG #1854).

    The marker's own scope is unknowable (the export's intent is not recoverable from a misplaced
    marker), so this degrades exactly as the ``unknown`` arm above does: say what was found, say the
    scope was lost, and inline the body at THIS indentation rather than invent a construct for it.

    A ``@Disabled`` subtree never reaches here (:func:`_parse_statement` returns it before branches are
    split, so it carries none), and the explicit guard keeps it that way: its whole contract is that
    nothing under it is emitted as live code, which inlining a body would break."""
    if ctrl.kind == "disabled":
        return []
    strays = [b for b in ctrl.branches if not _renders_as_branch(ctrl.kind, b.kind)]
    if not strays:
        return []
    # The body is being lifted OUT of the loop it was written inside, so a ``LoopExit`` in it no
    # longer names that loop. Emitting a live ``break`` here would bind it to whatever loop encloses
    # the construct — a silent change of which loop exits — so the loop context is dropped and the
    # ``LoopExit`` degrades to its own marker instead.
    in_loop = in_loop and ctrl.kind not in _LOOP_KINDS
    pad = "    " * indent
    out: list[str] = []
    for branch in strays:
        out.append(
            f"{pad}# TODO: Corepoint {branch.source_verb} cannot continue a Corepoint "
            f"{ctrl.source_verb}{_hint(_comment_text(branch.detail))}"
        )
        if branch.body:
            out.append(
                f"{pad}#   its body is inlined below at THIS indentation — the branch's own scope "
                f"is lost, re-scope by hand"
            )
        out.extend(_generate_steps(branch.body, indent, in_loop=in_loop))
    return out


def _generate_conditional(ctrl: Control, indent: int, *, in_loop: bool) -> list[str]:
    """Render an ``If``/``ChooseFrom`` chain as dead-conditioned ``if``/``elif``/``else`` blocks.

    A Corepoint condition is not a Python expression, so every branch condition is an explicit ``False``
    beside the original text — the generated module is inert until a human writes the real test, rather
    than silently taking a branch the export never meant."""
    pad = "    " * indent
    label = _comment_text(ctrl.detail)
    out: list[str] = []
    if ctrl.kind == "case":
        out.append(
            f"{pad}# Corepoint {ctrl.source_verb}: {label}" if label else f"{pad}# Corepoint"
        )
        # Statements before the first ``Matching`` arm run unconditionally in the export too.
        out.extend(_generate_steps(ctrl.body, indent, in_loop=in_loop))
        opened = False
    else:
        out.append(f"{pad}if False:  # TODO: Corepoint {ctrl.source_verb} condition{_hint(label)}")
        out.extend(_block_body(ctrl.body, indent + 1, in_loop=in_loop))
        opened = True

    last = len(ctrl.branches) - 1
    for i, branch in enumerate(ctrl.branches):
        note = _comment_text(branch.detail)
        if branch.kind == "else" and opened and i == last:
            # A bare ``else:`` under a DEAD (``False``) opener runs its body for EVERY message — the
            # exact inversion of the source, and the reason conditions are placeholders in the first
            # place. While the chain above is still dead, the fallback must be dead too.
            out.append(
                f"{pad}elif False:  # TODO: Corepoint {branch.source_verb} — the If/ElseIf above is "
                f"still a dead placeholder, so a bare `else:` would run this branch for EVERY "
                f"message. Write the If condition, then restore `else:`."
            )
        elif not opened:
            out.append(f"{pad}if False:  # TODO: Corepoint {branch.source_verb}{_hint(note)}")
            opened = True
        else:
            out.append(f"{pad}elif False:  # TODO: Corepoint {branch.source_verb}{_hint(note)}")
        out.extend(_block_body(branch.body, indent + 1, in_loop=in_loop))
    return out


def _hint(label: str) -> str:
    return f" — hand-finish: {label}" if label else " — hand-finish"


def _block_body(steps: tuple[Step, ...], indent: int, *, in_loop: bool) -> list[str]:
    """Render an indented block body, guaranteeing at least one statement so the module still parses."""
    out = _generate_steps(steps, indent, in_loop=in_loop)
    if not any(not line.lstrip().startswith("#") for line in out):
        out.append("    " * indent + "pass")
    return out


def _disabled_lines(ctrl: Control, pad: str) -> list[str]:
    """Render a ``@Disabled`` subtree as commented-out pseudo-source — visible, never live."""
    out = [
        f"{pad}# DISABLED in Corepoint (@Disabled) — preserved for review, NOT emitted as live code:",
        f"{pad}#   {ctrl.source_verb}: {_comment_text(ctrl.detail)}",
    ]
    out.extend(_disabled_body(ctrl.body, pad, 2))
    return out


def _disabled_body(steps: tuple[Step, ...], pad: str, depth: int) -> list[str]:
    out: list[str] = []
    prefix = f"{pad}#{'  ' * depth}"
    for step in steps:
        if isinstance(step, Action):
            # ``args`` are already rendered literals (escaped by _lit); ``source_class`` is not. A
            # write to a local other than msg names it, so re-enabling it keeps its message.
            on = "" if step.target == "msg" else f" on {step.target}"
            out.append(
                f"{prefix}{_comment_text(step.source_class, 60)} -> "
                f"{step.vocabulary}({', '.join(step.args)}){on}"
            )
        elif isinstance(step, UnmappedAction):
            out.append(f"{prefix}{_comment_text(step.source_class, 60)} (no vocabulary mapping)")
        else:
            out.append(f"{prefix}{step.source_verb}: {_comment_text(step.detail)}")
            out.extend(_disabled_body(step.body, pad, depth + 1))
            for branch in step.branches:
                out.append(f"{prefix}{branch.source_verb}: {_comment_text(branch.detail)}")
                out.extend(_disabled_body(branch.body, pad, depth + 1))
    return out


def _vocabulary_used(steps: tuple[Step, ...]) -> set[str]:
    """Every vocabulary helper the step tree calls (drives the generated import line)."""
    used: set[str] = set()
    for step in steps:
        if isinstance(step, Action):
            used.add(step.vocabulary)
        elif isinstance(step, Control) and step.kind != "disabled":
            used |= _vocabulary_used(step.body)
            for branch in step.branches:
                used |= _vocabulary_used(branch.body)
    return used


def _has_inline_send(steps: tuple[Step, ...]) -> bool:
    """Whether the tree carries a ``MsgSend`` that must accumulate into a ``sends`` list."""
    return _any_live_control(steps, lambda ctrl: ctrl.kind == "send" and bool(ctrl.args))


def _has_refusal(steps: tuple[Step, ...]) -> bool:
    """Whether the tree renders a refused ``MsgSend`` or ``MsgCreate`` as a live ``raise``."""
    return _any_live_control(steps, lambda ctrl: bool(ctrl.refusal))


def _builds_a_message(ctrl: Control) -> bool:
    """Whether ``ctrl`` renders a ``Message.parse`` (a ``MsgCreate`` with a skeleton)."""
    return ctrl.kind == "create" and not ctrl.refusal


def _any_live_control(steps: tuple[Step, ...], test: Callable[[Control], bool]) -> bool:
    """Whether any live (not ``@Disabled``) control in the tree, branches included, passes ``test``."""
    for step in steps:
        if not isinstance(step, Control) or step.kind == "disabled":
            continue
        if test(step):
            return True
        if _any_live_control(step.body, test) or any(
            _any_live_control(b.body, test) for b in step.branches
        ):
            return True
    return False


# --- top-level entry point ---------------------------------------------------


def _verify_compilable(source: str, target: Path) -> None:
    """Refuse generated source CPython cannot compile, before it reaches disk as a config module.

    :func:`generate_module` builds the module as a STRING, so without this nothing on the import path
    ever asked CPython whether the result parses -- the accept-and-drop the width note near
    ``_MAX_NESTING`` records. Catching only the obvious class would repeat that defect, so the tuple
    is deliberately broad: at least these four are reachable, and each is measured, not assumed.

    * ``SyntaxError`` -- a codegen bug, and what 3.14 raises for a NUL in the source (``ValueError``
      on older builds).
    * ``MemoryError`` -- the width wall. A bounded parser-arena limit rather than heap exhaustion,
      so the interpreter is fully usable afterwards.
    * ``RecursionError`` -- the compiler re-descending source this module emitted; ``_MAX_NESTING``
      bounds only this module's own walk. A flat chain of about 20,000 operands reaches it.
    * ``ValueError`` -- covers ``UnicodeEncodeError``, which a lone surrogate reaching the source
      raises. That is why the tuple names a BASE class here rather than one more leaf: enumerating
      leaves is how the original defect was written.

    Not a merge candidate with the lens's ``_assert_reparses``, which does the same job for rewritten
    Handlers: it raises a different error type, and its own ``except`` is narrower than this one."""
    name = str(target)
    try:
        compile(source, name, "exec")
    except (SyntaxError, ValueError, MemoryError, RecursionError) as exc:
        # Report the compiler's own message: it names the limit or character that was rejected, which
        # a bare "could not be generated" would hide from the operator deciding what to do next.
        raise CorepointImportError(
            f"generated module {name!r} could not be compiled and was not written: "
            f"{type(exc).__name__}: {exc}"
        ) from exc


def import_corepoint(export_path: str | Path, out_dir: str | Path) -> ImportResult:
    """Parse the export at ``export_path`` and write one config module per channel into ``out_dir``.

    Returns the :class:`ImportResult` count-and-log summary. Raises :class:`CorepointImportError` on a
    malformed export -- including one that is not valid UTF-8, and one whose generated module CPython
    cannot parse -- and :class:`OSError` on a filesystem failure (the CLI maps both to a clean
    error)."""
    epath = Path(export_path)
    unreadable: str | None = None
    try:
        text = epath.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        # `UnicodeDecodeError` subclasses `ValueError`, NOT `OSError` -- catching only the latter let a
        # non-UTF-8 export escape as a raw traceback instead of the clean `CorepointImportError` this
        # function's own docstring promises. Same shape as `__main__.py`'s audit-anchor file reader.
        # Raised after the handler: the decode error's `.object` is the whole export (BACKLOG #2085).
        unreadable = f"cannot read export {epath}: {exc}"
    if unreadable is not None:
        raise CorepointImportError(unreadable)

    channels = parse_any(text, source_name=epath.stem)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    results: list[ChannelResult] = []
    assigned: set[str] = set()
    for ch in channels:
        # Two channels can resolve to the same ``module_name`` — either from equal source names or
        # because ``_sanitize`` folds distinct names ("DEMO ADT" vs "DEMO-ADT") onto one stem. Since the
        # module_name is BOTH the filename stem AND the emitted ``inbound()`` connection name, a naive
        # write would silently overwrite the earlier file (losing a channel while the summary claims
        # success) and collide in the registry. De-duplicate deterministically (``IB_DUP`` → ``IB_DUP_2``,
        # ``_3``, …), regenerate so the inbound name matches the new stem, and record the rename in the
        # result so the collision is surfaced — never a silent drop (count-and-log ethos).
        renamed_from: str | None = None
        module_name = ch.module_name
        if module_name in assigned:
            renamed_from = module_name
            n = 2
            while f"{ch.module_name}_{n}" in assigned:
                n += 1
            module_name = f"{ch.module_name}_{n}"
            ch = replace(ch, module_name=module_name)
        assigned.add(module_name)

        source = generate_module(ch)
        mapped = 0
        disabled = 0
        unmapped_classes: list[str] = []
        for h in ch.handlers:
            h_mapped, h_unmapped, h_disabled = _count_steps(h.steps, in_loop=False)
            mapped += h_mapped
            unmapped_classes.extend(h_unmapped)
            disabled += h_disabled
        filename = f"{module_name}.py"
        target = out / filename
        # Raising here leaves an earlier channel's file in place, as an ``OSError`` from the write
        # already would; the error names the module that failed and the command exits non-zero.
        _verify_compilable(source, target)
        target.write_text(source, encoding="utf-8")
        results.append(
            ChannelResult(
                module_name,
                filename,
                source,
                mapped,
                len(unmapped_classes),
                tuple(unmapped_classes),
                renamed_from,
                disabled,
            )
        )
    return ImportResult(tuple(results))


# Control kinds that ARE faithfully represented in the emitted Python (real ``if``/``for``/``try``/…),
# so they count as mapped. ``block`` is a section label (never an action, so never counted); ``exit``
# has no faithful form and ``unknown`` is an unmodelled element tag — both count unmapped, emitted as a
# TODO marker. The four ``_BRANCH_PARENT`` kinds are faithful only while a construct ADOPTS them, so a
# BRANCH asks :func:`_renders_as_branch` rather than this set, and an orphaned marker counts unmapped.
# ``break`` is faithful only inside a loop, so :func:`_count_steps` also reads its loop context: a
# ``LoopExit`` outside a loop is a TODO marker and counts unmapped (BACKLOG #1860). A ``send`` that is
# refused, or names no destination, is not sent either, and also counts unmapped; so does a refused
# ``create``, which renders as a raise rather than the build (BACKLOG #313).
_MAPPED_CONTROL_KINDS = frozenset(
    {
        "if",
        "elif",
        "else",
        "for",
        "while",
        "try",
        "except",
        "case",
        "match",
        "break",
        "send",
        "call",
        *_BINDING_KINDS,
    }
)


def _count_steps(steps: tuple[Step, ...], *, in_loop: bool) -> tuple[int, list[str], int]:
    """``(mapped, unmapped_source_names, disabled)`` over a step tree — the count-and-log accounting.

    Every source element lands in exactly one bucket: emitted as a vocabulary call or as real control
    flow (*mapped*), emitted as an in-place TODO marker or a refusal — at least an unmapped verb, an
    ``exit``, a ``LoopExit`` outside a loop, an element whose tag is not modelled at all, a
    ``MsgSend`` that is refused or names no destination, and a refused ``MsgCreate`` (*unmapped*), or
    preserved as
    commented-out pseudo-source under a ``@Disabled`` element or action-list (*disabled*). Nothing is
    ever silently dropped.

    The names go through :func:`_comment_text` because the CLI prints them: the import summary is the
    count-and-log record a migrator trusts, and a JSON export naming a class
    ``"Foo\\n  IB_X.py (400 mapped)"`` would otherwise forge a line in it. Same escape, different sink
    — a terminal rather than a generated module — and the same reason, which is that ``class`` is an
    arbitrary export string that has been through no grammar.

    ``in_loop`` is threaded exactly as the render threads it, because the render emits a real
    ``break`` for a ``LoopExit`` only inside a loop and a TODO marker everywhere else. Counting every
    ``break`` mapped reported that marker as shipped (BACKLOG #1860)."""
    mapped = 0
    unmapped: list[str] = []
    disabled = 0
    for step in steps:
        if isinstance(step, Action):
            mapped += 1
        elif isinstance(step, UnmappedAction):
            unmapped.append(_comment_text(step.source_class, 60))
        elif step.kind == "disabled":
            # Counted as one preserved element; its whole subtree rides along in the comment block.
            disabled += 1
        else:
            if (
                step.refusal
                or (step.kind == "send" and not step.args)
                or (step.kind == "call" and not step.body)
            ):
                # Rendered as a raise or a bare TODO, never as the send, the build or the inlined
                # list, so not reported as shipped.
                unmapped.append(step.source_verb)
            elif (
                step.kind in _MAPPED_CONTROL_KINDS
                and step.kind not in _BRANCH_PARENT
                and (step.kind != "break" or in_loop)
            ):
                mapped += 1
            elif step.kind in ("exit", "unknown", "break") or step.kind in _BRANCH_PARENT:
                # "unknown": an unmodelled element TAG. A ``_BRANCH_PARENT`` kind here is a branch
                # marker standing where a statement should be, with no construct to continue: its
                # kind names real Python control flow, so it sits in ``_MAPPED_CONTROL_KINDS``, but
                # only an ADOPTED marker is ever EMITTED as control flow and an orphan degrades to a
                # TODO marker (BACKLOG #1854). Either way it is counted here (and surfaced by name in
                # ``unmapped_classes``) so it is reported, never skipped — its body counts on below.
                # A "break" reaches here only outside a loop, where the render marks it (#1860).
                unmapped.append(step.source_verb)
            # The loop context the render gives each body: a loop's own body is inside it, and a
            # branch of a loop is a stray the render lifts OUT of it (see :func:`_stray_branches`).
            is_loop = step.kind in _LOOP_KINDS
            nested_trees = (
                (step.body, in_loop or is_loop),
                *((b.body, in_loop and not is_loop) for b in step.branches),
            )
            for nested, nested_in_loop in nested_trees:
                n_mapped, n_unmapped, n_disabled = _count_steps(nested, in_loop=nested_in_loop)
                mapped += n_mapped
                unmapped.extend(n_unmapped)
                disabled += n_disabled
            for branch in step.branches:
                # A branch the render cannot emit as control flow becomes a TODO marker instead, so
                # it lands in the unmapped bucket; its body statements are real and counted above.
                if _renders_as_branch(step.kind, branch.kind):
                    mapped += 1
                else:
                    unmapped.append(branch.source_verb)
    return mapped, unmapped, disabled


# --- rendering + validation helpers ------------------------------------------


def _lit(value: Any) -> str:
    """Render ``value`` as a SAFE Python literal via :func:`json.dumps`, or raise.

    ``json.dumps`` emits a fully-escaped double-quoted string / list / dict literal, so an untrusted
    export value (even one containing quotes, backslashes, or newlines) rides across as inert data and
    cannot break out of the literal to inject code (CLAUDE.md §5/§8). Two properties of the output are
    load-bearing, and they are why this stays :func:`json.dumps` rather than :func:`repr`:

    * The output is **valid JSON**, which :func:`_collect_sends` relies on — it recovers a ``MsgSend``
      destination by ``json.loads``-ing the rendered argument back. ``repr`` renders a single-quoted
      Python string that ``json.loads`` rejects, so the shipped XML fixture would die on an uncaught
      ``JSONDecodeError`` before any module was written.
    * The output is **double-quoted**, which is ruff's canonical form, so a generated module needs no
      reformatting pass to satisfy the project's own format gate.

    The JSON and Python literal grammars are not the same grammar, though, and the overlap is what
    :func:`_assert_renderable` polices. ``ensure_ascii=False`` is part of the same job: the default
    ASCII escaping turns an astral code point into a ``\\uXXXX`` **surrogate pair** that Python re-reads
    as two lone surrogates, so the raw character is the value-preserving rendering."""
    _assert_renderable(value)
    return json.dumps(value, ensure_ascii=False)


def _assert_renderable(value: Any, where: str = "") -> None:
    """Refuse a value :func:`json.dumps` would render into something the module cannot carry.

    Walks containers, because the unguarded values are not only the top-level ones: an
    ``ItemCodeLookup`` passes its whole ``table`` through :func:`_lit`, so ``{"table": {"M": null}}``
    renders ``{"M": null}`` and raises ``NameError`` the moment the generated module is imported.
    Refusing every non-string scalar instead would be wrong in the other direction — the ``table``
    dict and an ``ItemSplit`` ``destinations`` list are legitimate, working input.

    ``where`` names the position inside the container, so a 200-entry lookup table reports which entry
    is the bad one rather than only that one of them is."""
    if isinstance(value, str):
        _assert_encodable(value, where)
        return
    if value is None or isinstance(value, bool):  # bool before int — bool is an int subclass
        # json.dumps writes null/true/false; Python reads all three as undefined NAMES.
        raise CorepointImportError(
            f"export value{where} is the JSON scalar {json.dumps(value)}, which is not a Python "
            "literal — supply a quoted string instead"
        )
    if isinstance(value, float) and not isfinite(value):
        # json.dumps writes NaN/Infinity/-Infinity by default; Python reads all three as names.
        raise CorepointImportError(
            f"export value{where} is a non-finite number, which is not a Python literal"
        )
    if isinstance(value, (int, float)):
        return
    if isinstance(value, list):
        for i, item in enumerate(value):
            _assert_renderable(item, f"{where}[{i}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CorepointImportError(
                    f"export value{where} has a non-string key {key!r}; json.dumps would silently "
                    "coerce it to a string, changing the value the module carries"
                )
            _assert_encodable(key, f"{where} key {key!r}")
            _assert_renderable(item, f"{where}[{key!r}]")
        return
    raise CorepointImportError(
        f"export value{where} is of type {type(value).__name__}, which has no literal form"
    )


def _assert_encodable(text: str, where: str) -> None:
    """Refuse a string carrying an unpaired surrogate.

    A lone surrogate survives ``json.dumps`` AND Python's own parser, then raises
    ``UnicodeEncodeError`` when the module is written as UTF-8 — a failure at the very last step,
    where the traceback blames the file write rather than the export that caused it. Performing the
    encode is the check: it is the same operation :func:`import_corepoint` will perform later, so
    there is no second definition of "encodable" to drift out of step with it."""
    try:
        text.encode("utf-8")
    except UnicodeEncodeError as exc:
        unencodable = str(exc)  # names one code point and its position, never the text around it
    else:
        return
    # Raised after the handler: the encode error's `.object` is the whole value (BACKLOG #2085).
    raise CorepointImportError(
        f"export value{where} carries an unpaired surrogate code point, which cannot be "
        f"encoded as UTF-8 in a generated module: {unencodable}"
    )


def _comment_text(text: str, limit: int = 200) -> str:
    """Flatten untrusted text for safe carriage inside a generated ``#`` comment.

    THE single boundary for text crossing into generated Python as a comment, and it is applied at the
    RENDER site rather than where the value is built: a comment is not a literal, so it needs a
    different escape from :func:`_lit`, and there are more places that build an ``UnmappedAction``
    than there are places that render one. Three jobs, in order:

    * Every run of whitespace — crucially including newlines — collapses to a single space, so a
      crafted ``@Data``/``@Comment`` carrying a line break cannot escape the ``#`` and become a
      statement in the generated module (CLAUDE.md §5/§8).
    * The control characters that are *not* whitespace are then deleted. NUL is the member that
      matters: Python refuses to compile a source string containing one, so a single NUL in an
      export's action-class name turns the whole generated module into a file that cannot be
      imported. The alphabet comes from :mod:`messagefoundry.controlchars` rather than being spelled
      out again here — see that module on why the test lives in exactly one place.
    * Long text is elided, so one pathological value cannot produce a multi-kilobyte comment line."""
    flat = strip_control_chars(" ".join(text.split()))
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


def _req_str(obj: dict[str, Any], key: str, ctx: str) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or not value:
        raise CorepointImportError(f"{ctx}: missing or non-string required field {key!r}")
    return value


def _opt_str(obj: dict[str, Any], key: str) -> str | None:
    value = obj.get(key)
    return value if isinstance(value, str) and value else None


# Reduce an arbitrary export name to a safe Python identifier / filename stem: keep word chars, fold the
# rest to underscores, ensure it does not start with a digit and is not a Python keyword.
_NON_IDENT = re.compile(r"\W+")


def _sanitize(name: str) -> str:
    ident = _NON_IDENT.sub("_", name).strip("_")
    if not ident:
        ident = "channel"
    if ident[0].isdigit():
        ident = f"c_{ident}"
    if keyword.iskeyword(ident):
        ident = f"{ident}_"
    return ident


# A generated CONNECTION name must also pass the loader's rule (BACKLOG #1107), which is stricter than
# a Python identifier: ASCII only, and bounded. So a connection name gets this second fold, and only a
# connection name does -- handler, router and ``def`` names keep ``_sanitize`` alone. A name that
# already passes the rule is returned unchanged, so a legal hyphenated name is never renamed.
_NON_CONNECTION = re.compile(r"[^A-Za-z0-9_-]+")
# Headroom under the rule's ceiling for the writer's ``_<n>`` de-duplication suffix, and, where the
# name is also a file stem, for ``.py`` inside a 255-character filename.
_CONNECTION_NAME_BUDGET = CONNECTION_NAME_MAX_LENGTH - 16


def _connection_name(name: str) -> str:
    if is_connection_name(name) and len(name) <= _CONNECTION_NAME_BUDGET:
        return name
    folded = _NON_CONNECTION.sub("_", name).strip("_-")
    if not folded:
        folded = "channel"
    if not ("A" <= folded[0].upper() <= "Z"):
        folded = f"c_{folded}"
    return folded[:_CONNECTION_NAME_BUDGET]
