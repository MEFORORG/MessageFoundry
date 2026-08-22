# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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
hand-finish`` marker (plus, when a target field is recoverable, a best-effort field-preserving
``msg.set`` stub), its subtree is parsed and inlined beneath it, and the import summary counts it.
Control flow is emitted as real nested Python (``if``/``for``/``while``/``try``) whose *condition* is
left as an explicit, dead (`False`) hand-finish placeholder — a Corepoint condition expression is not
Python and is never guessed. ``@Disabled`` is honoured at **every** level — a single statement, a
``<Block>``, a whole ``<ActionList>``, the ``<Package>`` — and always renders as commented-out
pseudo-source: never live code, and a disabled action-list is not routed to.

**Security (untrusted input).** A Corepoint export is untrusted *data*, never instructions
(CLAUDE.md §5/§8). Every value lifted from the export into generated Python source is rendered through
:func:`json.dumps`, which emits a fully-escaped string/list/dict **literal** — a stray quote, newline,
or backslash cannot break out of the literal into executable code, so a hostile export cannot inject
code into the generated module. Text that rides into a *comment* is flattened by
:func:`_comment_text` (newlines collapsed), so a crafted ``@Data``/``@Comment`` cannot escape the
``#`` into a statement. XML is parsed through **defusedxml** with ``forbid_dtd``/``forbid_entities``/
``forbid_external`` all on, so a billion-laughs or external-entity payload raises instead of expanding.
Paths ride across as data to :meth:`Message.set` at run time.

Pure (parse + string codegen): no network, no message content, no dependency beyond the already-in-tree
``defusedxml`` — safe to run anywhere.
"""

from __future__ import annotations

import html
import json
import keyword
import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any
from xml.etree.ElementTree import (  # nosec B405 — exception type only; every parse goes through defusedxml
    ParseError,
)

from defusedxml.common import DefusedXmlException
from defusedxml.ElementTree import fromstring as _xml_fromstring

if TYPE_CHECKING:  # runtime never needs the class — only the annotations do
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
    """The export could not be parsed into the ADR 0086 model (malformed XML/JSON or a missing field).

    A subclass of :class:`ValueError`; the CLI turns it into a clean error + non-zero exit. The
    importer treats the export as untrusted data, so a structural problem — including a rejected DTD
    or entity payload — is reported, never raised as an uncaught traceback."""


# --- intermediate action model ----------------------------------------------


@dataclass(frozen=True)
class Action:
    """A mapped transform step — a v1 vocabulary call ready to emit.

    ``args`` are already-rendered Python source fragments for the positional arguments *after* the
    leading ``msg``; ``keywords`` are ``(name, rendered_value)`` pairs. ``source_class`` is the
    originating Corepoint action class (kept for provenance in comments/summaries)."""

    source_class: str
    vocabulary: str
    args: tuple[str, ...]
    keywords: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class UnmappedAction:
    """A source action with no v1 vocabulary mapping — emitted as a visible TODO + best-effort stub.

    ``stub_path`` is the recovered target field (``None`` when the export names none, so only the TODO
    marker is emitted). ``detail`` is a short human note for the marker."""

    source_class: str
    stub_path: str | None
    detail: str


@dataclass(frozen=True)
class Control:
    """A non-leaf element of the ``<Package>`` control-flow tree — a construct with a nested body.

    ``kind`` is the *emitted* shape, deliberately named after the Python it becomes so the generator
    stays a dumb renderer:

    ``"block"``   a ``<Block>`` section label / ``<Call>`` inline — a **comment** plus its body at the
                  *same* indentation (a ``<Block>`` is a label, never an action, so it emits no step).
    ``"call"``    an ``ActionListCall`` whose target list is inlined — rendered like ``"block"``.
    ``"if"``      with ``branches`` of kind ``"elif"``/``"else"``.
    ``"for"``     ``ForEach`` · ``"while"`` ``Loop`` · ``"break"`` ``LoopExit``.
    ``"try"``     with ``branches`` of kind ``"except"`` (``Catch``).
    ``"case"``    ``ChooseFrom``/``<Case>`` with ``branches`` of kind ``"match"`` (``Matching``).
    ``"send"``    a ``MsgSend`` — ``args`` carries the rendered destination-name literal (empty when
                  the export names none, which degrades to a TODO marker rather than a guess).
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

    module_name: str  # file stem + inbound connection name, e.g. IB_ACME_ADT
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

    # Unrecognized: never dropped. Recover a plausible target field for a best-effort passthrough stub.
    stub = raw.get("target") or raw.get("destination") or raw.get("source")
    stub_path = stub if isinstance(stub, str) else None
    return UnmappedAction(cls, stub_path, f"no v1 vocabulary mapping for Corepoint {cls}")


# --- export parsing (defensive; untrusted data) ------------------------------


def parse_export(text: str) -> tuple[Channel, ...]:
    """Parse the **superseded synthetic JSON** export model (ADR 0086 §2(a)) into the channel model.

    Kept working for the fixtures/tooling written against it before the real shape was known; the
    validated path is :func:`parse_package` (XML). :func:`parse_any` dispatches between them.

    Defensive throughout: a JSON syntax error or a structural violation raises
    :class:`CorepointImportError` (never an uncaught traceback), because the export is untrusted data.
    Returns one :class:`Channel` per exported channel."""
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CorepointImportError(f"export is not valid JSON: {exc}") from exc
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
    module_name = _sanitize(_opt_str(inbound, "name") or f"IB_{ident.upper()}")

    dests_raw = ch.get("destinations", [])
    if not isinstance(dests_raw, list):
        raise CorepointImportError(f"channel {name!r} 'destinations' must be an array")
    destinations: list[Destination] = []
    for j, d in enumerate(dests_raw):
        if not isinstance(d, dict):
            raise CorepointImportError(f"channel {name!r} destination #{j} must be an object")
        d_connector, d_call = _render_connector(d, name, inbound=False)
        d_name = _opt_str(d, "name") or f"OB_{ident.upper()}_{j + 1}"
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
        dests = tuple(dests_raw)
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
    # ``set_field(msg, "MSH-6", "\"ACME\"")``, a value carrying two stray quote characters.
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


def _subject_handle(action_list: Element) -> frozenset[str]:
    """The one message handle an action-list's steps may be mapped against, or ``None``.

    A Corepoint action-list manipulates **several** messages at once (input, output, scratch), while a
    MessageFoundry Handler has exactly **one** ``msg``. So a field write is only faithfully
    representable when we can say *which* handle became ``msg`` — and in the validated corpus that is
    genuinely ambiguous for a large minority of lists (most lists carry 2+ handles, and more of them
    deliver a handle *other* than their input than deliver the input itself, so "the input handle" is
    the wrong answer).

    In a Handler, ``msg`` is the message that arrived **and** the message returned by ``Send`` — the
    two are the same object. So the subject is the list's **input** handle, and only when that same
    handle is what the list delivers. A list that builds a *separate* output tree and sends that has
    no equivalent at all: writing its fields onto ``msg`` would mutate the inbound message, which is
    not the message Corepoint was populating. (This is not hypothetical — more lists deliver a
    non-input handle than deliver the input one, which is exactly why "the input handle" alone is the
    wrong predicate.)

    Requires, therefore: exactly one distinct ``input-handle`` in the list, and either no ``MsgSend``
    at all or a ``MsgSend`` that delivers that handle **or a whole-tree clone of it**. A clone — a
    ``MsgTreeCopy`` of the input's ROOT into another handle — holds exactly the input's content, so a
    write to it is a write to what ``msg`` will be; a *partial* copy is not, and is excluded, because
    the destination tree then holds only the sub-node that was copied.

    Anything else returns an empty set and **every** path-bearing statement in the list degrades to a
    TODO — the honest output, because a cross-message write rendered as ``msg.set`` silently mutates
    the wrong message."""
    inputs: set[str] = set()
    delivered: set[str] = set()
    root_copies: list[tuple[str, str]] = []  # (source handle, destination handle)
    for elem in action_list.iter():
        data = _attr(elem, "Data")
        if not data:
            continue
        tokens = parse_roles(data)
        inputs.update(t.text for t in tokens if t.source_class == "input-handle")
        verb = _role_verb(tokens).lower()
        operands = _operands_from_roles(tokens)
        if verb == "msgsend" and operands and operands[0].kind == "handle":
            delivered.add(operands[0].text)
        elif verb == "msgtreecopy" and len(operands) == 2:
            src, dst = operands
            if (
                src.kind == "path"
                and dst.kind == "path"
                and _is_root_path(src.text)
                and _is_root_path(dst.text)
            ):
                root_copies.append((src.handle, dst.handle))
    if len(inputs) != 1:
        return frozenset()
    subject = next(iter(inputs))
    same = {subject}
    # A clone chain is followed transitively, but only ever forward from the input.
    for _ in range(len(root_copies)):
        grew = {dst for src, dst in root_copies if src in same}
        if grew <= same:
            break
        same |= grew
    return frozenset(same) if delivered <= same else frozenset()


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
    """The first operand that resolves to an HL7 path — the best-effort stub target for a TODO."""
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

    detail = (
        f"no v1 vocabulary mapping for Corepoint {verb}: {_comment_text(statement)}"
        if verb
        else f"statement does not begin with a verb: {_comment_text(statement)}"
    )
    return UnmappedAction(verb or "<unparsed>", _first_path(operands), detail)


def _subject_field(operand: Operand, subject: frozenset[str]) -> str | None:
    """The :class:`Message` path this operand addresses, or ``None`` if it is not ``msg``'s own field.

    Three conditions, all required: the list has an unambiguous subject handle, the operand addresses
    **that** handle, and its leaf resolves to HL7 coordinates. Relaxing any one of them produces code
    that writes a real field with the wrong value — the failure mode this importer exists to avoid."""
    if operand.kind != "path" or operand.handle not in subject:
        return None
    return _corepoint_path(operand.text)


def _decline_reason(operands: tuple[Operand, ...], subject: frozenset[str]) -> str:
    """Why a role-parsed statement could not be mapped — named precisely so a human can act on it.

    A generic "no mapping" marker makes 5,000 TODOs look identical; naming the *cause* is what lets a
    migrator triage them (a cross-message write needs a second Handler; an unresolvable node path needs
    a field decision; a variable needs hand-written Python)."""
    paths = [o for o in operands if o.kind == "path"]
    if not subject and paths:
        return (
            "the action-list works on several messages and none is identifiably the one delivered"
        )
    if any(o.handle not in subject for o in paths):
        return "addresses a different message than the one this handler delivers (cross-message)"
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
    subject: frozenset[str],
    *,
    connectives: tuple[str, ...],
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
    if qualified or not {c.lower() for c in connectives} <= allowed:
        return None
    if in_control:
        # Inside an If/ForEach/Loop/Try the statement is conditional or repeated in the SOURCE, but the
        # emitted condition is a dead placeholder and the loop is `for _item in []`. A real call there
        # would run under a condition nobody wrote — and in a loop it would rewrite occurrence 1 every
        # pass. Only a top-level statement is unambiguous, so only a top-level statement maps.
        return None

    if lowered == "itemcopy" and len(operands) == 2:
        dst = _subject_field(operands[1], subject)
        if _writable(dst):
            assert dst is not None
            if operands[0].kind == "literal" and operands[0].quoted:
                # A constant source is a set, not a copy — the vocabulary's exact equivalent. Only a
                # QUOTED literal is taken: a bare literal span is the exporter's un-delimited form and
                # its extent is not reliably recoverable.
                return Action(verb, "set_field", (_lit(dst), _lit(operands[0].text)))
            src = _subject_field(operands[0], subject)
            if src is not None:
                # NOT mapped to ``copy_field``: it writes "" when the source is absent, which would
                # CLEAR a populated destination, and nothing in the export says Corepoint does that
                # rather than leave the destination untouched. Declined deliberately (see _decline).
                return None
    elif lowered == "itemclear" and len(operands) == 1:
        target = _subject_field(operands[0], subject)
        if _writable(target):
            assert target is not None
            # Clearing is setting empty; ``Message.set`` re-encodes structurally.
            return Action(verb, "set_field", (_lit(target), _lit("")))
    elif lowered == "itemappend" and len(operands) == 2:
        # ``ItemAppend "<suffix>" to <target>`` — value FIRST, target second.
        target = _subject_field(operands[1], subject)
        if _writable(target) and operands[0].kind == "literal" and operands[0].quoted:
            assert target is not None
            return Action(verb, "append_to_field", (_lit(target), _lit(operands[0].text)))
    return None


def _decline(verb: str, operands: tuple[Operand, ...], subject: frozenset[str]) -> UnmappedAction:
    """Turn a declined role-parsed statement into a TODO marker that says *why*, plus a safe stub.

    The stub target is the first operand that is genuinely ``msg``'s own field, so the hand-finish keeps
    the intended field visible without inventing one when nothing resolves."""
    # NO live stub. The "best-effort passthrough" ``msg.set(p, msg.field(p) or "")`` is not the inert
    # marker its comment claims: ``Message.set`` RAISES ``KeyError`` on an absent segment, and on a
    # present segment with an absent field it *materialises* the field and its empty components on the
    # wire. A line whose only job is to stay visible must not be able to change the message or
    # dead-letter it, so the recovered target rides into the comment instead.
    target = next(
        (field for field in (_subject_field(o, subject) for o in operands) if field is not None),
        None,
    )
    reason = _decline_reason(operands, subject)
    detail = f"{reason}; intended target {target}" if target else reason
    return UnmappedAction(verb, None, detail)


def _role_send_args(operands: tuple[Operand, ...]) -> tuple[str, ...]:
    """The rendered destination-name literal for a role-parsed ``MsgSend``, or ``()``.

    The validated grammar is ``MsgSend <handle> to connection "<name>"``, so the destination is the
    statement's first **literal** — precise where the flat heuristic had to guess at the first quoted
    token. Sanitized in one place, exactly as :func:`_send_args`, so a hostile name cannot ride into the
    generated wiring as a traversal path."""
    for operand in operands:
        if operand.kind == "literal" and operand.text.strip():
            return (_lit(_sanitize(operand.text)),)
    return ()


def _split_branches(steps: list[Step]) -> tuple[tuple[Step, ...], tuple[Control, ...]]:
    """Split a container body at its branch markers into ``(body, branches)``.

    The export writes ``Else``/``ElseIf``/``Catch``/``Matching`` as ordinary statements *inside* the
    construct's own ``<List>``, so everything after such a marker belongs to that branch. Recursing
    keeps successive branches siblings (``if`` → ``elif`` → ``else``), not nested."""
    for i, step in enumerate(steps):
        if isinstance(step, Control) and step.kind in _BRANCH_PARENT and not step.body:
            body, rest = _split_branches(steps[i + 1 :])
            return tuple(steps[:i]), (replace(step, body=body), *rest)
    return tuple(steps), ()


# How deep the ``<List>`` tree may nest. The walk is mutually recursive (list → statement → list), so
# an untrusted export nesting thousands of elements would otherwise exhaust the interpreter stack and
# surface as a RecursionError traceback instead of a clean, reported error (CLAUDE.md §6/§8). Real
# packages nest a handful of levels; 100 is far past any plausible hand-authored action-list.
_MAX_NESTING = 100


def _parse_list(
    container: Element, subject: frozenset[str], in_control: bool, depth: int = 0
) -> list[Step]:
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
            steps.extend(_parse_list(child, subject, in_control, depth + 1))
            continue
        # EVERY other child is a statement position and goes through _parse_statement — including a tag
        # this layer does not model, which comes back as an "unknown" marker plus its parsed subtree.
        # Skipping unmodelled tags here (as an earlier cut did, citing the <Connection>/<Codeset>/
        # <DataPoint> package subtrees) dropped whole subtrees silently: those subtrees are children of
        # <Package>, NEVER of a <List>, so the tolerance was applied exactly where statements live and a
        # <Switch> — or a <Lines> typo — vanished with its body. Untrusted input is still never a crash.
        produced = _parse_statement(child, subject, in_control, depth + 1)
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


def _container_steps(
    elem: Element, subject: frozenset[str], in_control: bool, depth: int = 0
) -> list[Step]:
    """The nested body of ``elem``, in document order — every child, whatever shape it takes.

    :func:`_parse_list` already flattens a ``<List>``/``<Actions>`` wrapper, so walking ``elem`` itself
    covers BOTH forms (the usual wrapped body and a direct statement child) *and* keeps a statement that
    is a **sibling** of the wrapper. Returning only the wrapper's children — as an earlier cut did the
    moment any wrapper existed — silently discarded those siblings, including an ``Else`` marker and its
    whole branch body."""
    return _parse_list(elem, subject, in_control, depth + 1)


def _parse_statement(
    elem: Element, subject: frozenset[str], in_control: bool, depth: int = 0
) -> list[Step]:
    """Parse one statement element into zero or more steps (a list, so a leaf can carry a body)."""
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
    # escapes"). A mapping may only fire when the statement's connectives fall inside that verb's known
    # set and it carries no qualifier — otherwise the emitted call would silently lose an operator.
    connectives = tuple(t.text for t in roles if t.role == "text" and t.text)
    qualified = any(t.role == "detail" for t in roles)
    # Prefer the role layer's verb, but keep the flat reading as a NAMING fallback: a handful of verbs
    # are not styled as a ``keyword`` span at all, and letting those collapse into "<unparsed>" would
    # throw away the one thing that makes a TODO triageable — which verb it was.
    verb = (_role_verb(roles) or flat_verb) if roles else flat_verb
    role_operands = _operands_from_roles(roles) if roles else ()

    source = _source_label(tag, verb)

    kind = _CONTAINER_KIND_BY_TAG.get(tag.lower())
    if kind is None:
        # A ``<Line>``: control flow is carried by the verb, everything else is a transform statement.
        kind = _KIND_BY_VERB.get(verb.lower())
    elif kind in ("block", "call") and verb.lower() in _KIND_BY_VERB:
        # ``<Call Data="ActionListCall …">`` — the verb is the more specific truth.
        kind = _KIND_BY_VERB[verb.lower()]

    # A construct NESTS its body under a placeholder condition; a ``<Block>``/``<Call>`` is a label
    # whose body stays at the same indentation, so it does not deepen control scope.
    body = _container_steps(elem, subject, in_control or kind in _NESTING_KINDS, depth)

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
        return [Control("unknown", tag, statement or note, body=tuple(body))]

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
        mapped: Action | UnmappedAction
        if roles and verb:
            role_mapped = _map_roles(
                verb,
                role_operands,
                subject,
                connectives=connectives,
                qualified=qualified,
                in_control=in_control,
            )
            mapped = (
                role_mapped if role_mapped is not None else _decline(verb, role_operands, subject)
            )
        elif statement:
            mapped = _map_statement(verb, operands, statement)
        else:
            # No statement at all — reported rather than skipped, because a silently-ignored element is
            # exactly the accept-and-drop this importer refuses (count-and-log).
            mapped = UnmappedAction(tag, None, f"<{tag}> carries no statement to translate")
        # An operator's ``@Comment`` — and the ``description``/``comment`` prose the role layer lifts
        # OUT of the statement — is preserved beside the step it annotates, never dropped.
        prose = note or _role_prose(roles)
        lead: list[Step] = [Control("block", "Comment", prose)] if prose else []
        return [*lead, mapped, *body]

    if kind == "send":
        # ``*body`` matters: a ``MsgSend`` element that carries a nested list would otherwise lose it
        # (the break/exit path below always kept its body — this one silently did not).
        args = _role_send_args(role_operands) if roles else _send_args(operands)
        return [Control("send", source, statement, args=args), *body]
    if kind in ("break", "exit"):
        return [Control(kind, source, statement), *body]
    if kind in ("block", "call"):
        # A ``<Block>`` is a section LABEL, not an action, and a ``<Call>``'s target list is inlined:
        # both emit a comment plus their body at the SAME indentation — never a step of their own.
        return [Control(kind, source, statement or note or tag, body=tuple(body))]

    inner, branches = _split_branches(body)
    detail = _strip_leading_verb(statement, verb)
    return [Control(kind, source, detail, body=inner, branches=branches)]


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
            return (_lit(_sanitize(name)),)
    return ()


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
    module_name = f"IB_{ident.upper()}"

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
        steps = tuple(_container_steps(action_list, _subject_handle(action_list), False))
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
    resurrect a switched-off send as live code — the one thing ``@Disabled`` must never do."""
    found: list[str] = []
    for step in steps:
        if not isinstance(step, Control) or step.kind == "disabled":
            continue
        if step.kind == "send" and step.args:
            name = json.loads(step.args[0])
            if name not in found:
                found.append(name)
        for nested in (*_collect_sends(step.body), *_collect_sends(step.branches)):
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
    row; a TODO stub degrades to an in-place ``code`` row — never a whole-file refusal)."""
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
        "# Copyright (C) 2026 MessageFoundry Organization and contributors",
        '"""Generated by `messagefoundry import corepoint` (ADR 0086) — REVIEW before production use.',
        "",
        *provenance,
        '"""',
        "",
    ]

    surface = ["Send", "handler", "inbound", "outbound", "router"]
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
            parts = [f"msg, {', '.join(step.args)}"] if step.args else ["msg"]
            for kw_name, kw_val in step.keywords:
                parts.append(f"{kw_name}={kw_val}")
            out.append(f"{pad}{step.vocabulary}({', '.join(parts)})")
        elif isinstance(step, UnmappedAction):
            out.append(f"{pad}# TODO: Corepoint {step.source_class} — hand-finish ({step.detail})")
            if step.stub_path is not None:
                # Best-effort passthrough: re-set the field to its own value so nothing is corrupted and
                # the intended target stays visible for the hand-finish (count-and-log; never dropped).
                out.append(
                    f'{pad}msg.set({_lit(step.stub_path)}, msg.field({_lit(step.stub_path)}) or "")'
                )
        else:
            out.extend(_generate_control(step, indent, in_loop=in_loop))
    return out


def _generate_control(ctrl: Control, indent: int, *, in_loop: bool) -> list[str]:
    """Render one control construct. Conditions are never guessed — they become dead placeholders."""
    pad = "    " * indent
    label = _comment_text(ctrl.detail)
    suffix = f" — hand-finish: {label}" if label else ""

    if ctrl.kind == "disabled":
        return _disabled_lines(ctrl, pad)
    if ctrl.kind in ("block", "call"):
        # A section label / an inlined call: a comment, then the body at the SAME indentation.
        head = f"Corepoint {ctrl.source_verb}"
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
        if not ctrl.args:
            return [
                f"{pad}# TODO: Corepoint {ctrl.source_verb} — hand-finish: no destination named "
                f"({label})"
            ]
        return [f"{pad}sends.append(Send({ctrl.args[0]}, msg))  # Corepoint {ctrl.source_verb}"]
    if ctrl.kind == "break":
        if in_loop:
            return [f"{pad}break  # Corepoint {ctrl.source_verb}"]
        return [f"{pad}# TODO: Corepoint {ctrl.source_verb} outside a loop — hand-finish{suffix}"]
    if ctrl.kind == "exit":
        # ``Returns``/``ActionListExit``/``ActionListStop`` end the list; a bare ``return`` here would
        # silently drop the handler's Sends, so the flow is flagged for a human, never guessed.
        return [f"{pad}# TODO: Corepoint {ctrl.source_verb} (ends this list){suffix}"]
    if ctrl.kind == "try":
        out = [f"{pad}try:"]
        out.extend(_block_body(ctrl.body, indent + 1, in_loop=in_loop))
        handlers = [b for b in ctrl.branches if b.kind == "except"] or None
        if handlers is None:
            out.append(f"{pad}except Exception:  # TODO: Corepoint Try with no Catch — hand-finish")
            out.append(f"{pad}    raise")
            return out
        for branch in handlers:
            note = _comment_text(branch.detail)
            out.append(
                f"{pad}except Exception:  # TODO: Corepoint {branch.source_verb} — hand-finish"
                + (f": {note}" if note else "")
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
            out.append(f"{prefix}{step.source_class} -> {step.vocabulary}({', '.join(step.args)})")
        elif isinstance(step, UnmappedAction):
            out.append(f"{prefix}{step.source_class} (no vocabulary mapping)")
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
    for step in steps:
        if not isinstance(step, Control) or step.kind == "disabled":
            continue
        if step.kind == "send" and step.args:
            return True
        if _has_inline_send(step.body) or any(_has_inline_send(b.body) for b in step.branches):
            return True
    return False


# --- top-level entry point ---------------------------------------------------


def import_corepoint(export_path: str | Path, out_dir: str | Path) -> ImportResult:
    """Parse the export at ``export_path`` and write one config module per channel into ``out_dir``.

    Returns the :class:`ImportResult` count-and-log summary. Raises :class:`CorepointImportError` on a
    malformed export and :class:`OSError` on a filesystem failure (the CLI maps both to a clean error)."""
    epath = Path(export_path)
    try:
        text = epath.read_text(encoding="utf-8")
    except OSError as exc:
        raise CorepointImportError(f"cannot read export {epath}: {exc}") from exc

    channels = parse_any(text, source_name=epath.stem)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    results: list[ChannelResult] = []
    assigned: set[str] = set()
    for ch in channels:
        # Two channels can resolve to the same ``module_name`` — either from equal source names or
        # because ``_sanitize`` folds distinct names ("ACME ADT" vs "ACME-ADT") onto one stem. Since the
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
            h_mapped, h_unmapped, h_disabled = _count_steps(h.steps)
            mapped += h_mapped
            unmapped_classes.extend(h_unmapped)
            disabled += h_disabled
        filename = f"{module_name}.py"
        (out / filename).write_text(source, encoding="utf-8")
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
# TODO marker.
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
    }
)


def _count_steps(steps: tuple[Step, ...]) -> tuple[int, list[str], int]:
    """``(mapped, unmapped_source_names, disabled)`` over a step tree — the count-and-log accounting.

    Every source element lands in exactly one bucket: emitted as a vocabulary call or as real control
    flow (*mapped*), emitted as an in-place TODO marker — an unmapped verb, an ``exit``, or an element
    whose tag is not modelled at all (*unmapped*), or preserved as commented-out pseudo-source under a
    ``@Disabled`` element or action-list (*disabled*). Nothing is ever silently dropped."""
    mapped = 0
    unmapped: list[str] = []
    disabled = 0
    for step in steps:
        if isinstance(step, Action):
            mapped += 1
        elif isinstance(step, UnmappedAction):
            unmapped.append(step.source_class)
        elif step.kind == "disabled":
            # Counted as one preserved element; its whole subtree rides along in the comment block.
            disabled += 1
        else:
            if step.kind in _MAPPED_CONTROL_KINDS:
                mapped += 1
            elif step.kind in ("exit", "unknown"):
                # "unknown": an unmodelled element TAG. Counted here (and surfaced by name in
                # ``unmapped_classes``) so it is reported, never skipped — its body counts on below.
                unmapped.append(step.source_verb)
            for nested in (step.body, *(b.body for b in step.branches)):
                n_mapped, n_unmapped, n_disabled = _count_steps(nested)
                mapped += n_mapped
                unmapped.extend(n_unmapped)
                disabled += n_disabled
            for branch in step.branches:
                if branch.kind in _MAPPED_CONTROL_KINDS:
                    mapped += 1
    return mapped, unmapped, disabled


# --- rendering + validation helpers ------------------------------------------


def _lit(value: Any) -> str:
    """Render ``value`` as a SAFE Python literal via :func:`json.dumps`.

    ``json.dumps`` emits a fully-escaped double-quoted string / list / dict literal that is also valid
    Python source, so an untrusted export value (even one containing quotes, backslashes, or newlines)
    rides across as inert data and cannot break out of the literal to inject code (CLAUDE.md §5/§8)."""
    return json.dumps(value)


def _comment_text(text: str, limit: int = 200) -> str:
    """Flatten untrusted text for safe carriage inside a generated ``#`` comment.

    Every run of whitespace — crucially including newlines — collapses to a single space, so a crafted
    ``@Data``/``@Comment`` carrying a line break cannot escape the ``#`` and become a statement in the
    generated module (CLAUDE.md §5/§8, the comment-side sibling of :func:`_lit`). Long text is elided
    so one pathological statement cannot produce a multi-kilobyte comment line."""
    flat = " ".join(text.split())
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
