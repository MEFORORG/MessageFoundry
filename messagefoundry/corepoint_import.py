# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Deterministic Corepoint action-list import → code-first ``@router``/``@handler`` modules (ADR 0086).

The **inverse** of the ADR 0076 §2 vocabulary table: where the lens *reads* a vocabulary-authored
Handler back into a typed action-list, this importer *writes* a Corepoint-style action-list forward
into a real ``.py`` config module that calls the same :mod:`messagefoundry.actions` vocabulary and
returns :class:`~messagefoundry.Send` against the :class:`~messagefoundry.parsing.message.Message`
API. The emitted ``.py`` is the **only** artifact and execution path — there is no interpreter and no
declarative model (CLAUDE.md §12 / ADR 0076).

**The input schema is SYNTHETIC-until-validated** (ADR 0086 §2): no real Corepoint export exists in
this repository (the #87 recon corpus is git-ignored), so the JSON shape parsed here is a *plausible*
model of a Corepoint action-list export, defined by that ADR and exercised only against synthetic
fixtures. Field names / structure will need reconciliation against a real export before this is used
on production channels.

**Every source action is accounted for (count-and-log ethos).** An action whose ``class`` maps to a
v1 vocabulary helper emits that call; an **unmapped** action is *never silently dropped* — it emits an
in-place ``# TODO: Corepoint <ActionClass> — hand-finish`` marker plus, when a target field is
recoverable, a best-effort field-preserving ``msg.set`` stub, and the import summary counts it.

**Security (untrusted input).** A Corepoint export is untrusted *data*, never instructions
(CLAUDE.md §5/§8). Every value lifted from the export into generated Python source is rendered through
:func:`json.dumps`, which emits a fully-escaped string/list/dict **literal** — a stray quote, newline,
or backslash cannot break out of the literal into executable code, so a hostile export cannot inject
code into the generated module. Paths ride across as data to :meth:`Message.set` at run time.

Pure + stdlib-only (``json`` parse, string codegen): no runtime dependency, no network, no message
content — safe to run anywhere.
"""

from __future__ import annotations

import json
import keyword
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

__all__ = [
    "CorepointImportError",
    "Action",
    "UnmappedAction",
    "Handler",
    "Destination",
    "Channel",
    "ChannelResult",
    "ImportResult",
    "parse_export",
    "generate_module",
    "import_corepoint",
]


class CorepointImportError(ValueError):
    """The export could not be parsed into the ADR 0086 model (malformed JSON or a missing field).

    A subclass of :class:`ValueError`; the CLI turns it into a clean error + non-zero exit. The
    importer treats the export as untrusted data, so a structural problem is reported, never raised as
    an uncaught traceback."""


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
class Handler:
    """One Corepoint handler: an ordered list of mapped/unmapped steps + the destinations it sends to."""

    name: str
    steps: tuple[Action | UnmappedAction, ...]
    destinations: tuple[str, ...]


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
                }
                for c in self.channels
            ],
            "total_mapped": self.total_mapped,
            "total_unmapped": self.total_unmapped,
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
    """Parse a Corepoint action-list export (ADR 0086 JSON) into the intermediate channel model.

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

    module_name = _opt_str(inbound, "name") or f"IB_{ident.upper()}"

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
        for step in h.steps:
            if isinstance(step, Action):
                used_vocab.add(step.vocabulary)

    lines: list[str] = [
        "# SPDX-License-Identifier: AGPL-3.0-or-later",
        "# Copyright (C) 2026 MessageFoundry Organization and contributors",
        '"""Generated by `messagefoundry import corepoint` (ADR 0086) — REVIEW before production use.',
        "",
        "This module was mechanically translated from a SYNTHETIC-schema Corepoint action-list export.",
        "The source schema is unvalidated against a real Corepoint export; verify field paths, routing,",
        "and any `# TODO: Corepoint ...` hand-finish markers below before deploying.",
        '"""',
        "",
    ]

    surface = ["Send", "handler", "inbound", "outbound", "router"]
    surface_imports = sorted({*surface, *used_connectors})
    lines.append(f"from messagefoundry import {', '.join(surface_imports)}")
    if used_vocab:
        lines.append(f"from messagefoundry.actions import {', '.join(sorted(used_vocab))}")
    lines.append("")

    # Endpoints: inbound (naming its router) + one outbound per destination.
    lines.append(
        f"inbound({_lit(channel.module_name)}, {channel.inbound_call}, router={_lit(channel.router_name)})"
    )
    for d in channel.destinations:
        lines.append(f"outbound({_lit(d.name)}, {d.call})")
    lines.append("")
    lines.append("")

    # Router: forwards to every handler (Corepoint routing is per-channel; refine by hand).
    handler_names = [h.name for h in channel.handlers]
    lines.append(f"@router({_lit(channel.router_name)})")
    lines.append("def route(msg):  # type: ignore[no-untyped-def]")
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


def _generate_handler(h: Handler) -> list[str]:
    lines = [f"@handler({_lit(h.name)})", f"def {h.name}(msg):  # type: ignore[no-untyped-def]"]
    body: list[str] = []
    for step in h.steps:
        if isinstance(step, Action):
            parts = [f"msg, {', '.join(step.args)}"] if step.args else ["msg"]
            for kw_name, kw_val in step.keywords:
                parts.append(f"{kw_name}={kw_val}")
            body.append(f"    {step.vocabulary}({', '.join(parts)})")
        else:
            body.append(f"    # TODO: Corepoint {step.source_class} — hand-finish ({step.detail})")
            if step.stub_path is not None:
                # Best-effort passthrough: re-set the field to its own value so nothing is corrupted and
                # the intended target stays visible for the hand-finish (count-and-log; never dropped).
                body.append(
                    f'    msg.set({_lit(step.stub_path)}, msg.field({_lit(step.stub_path)}) or "")'
                )

    # Return the Sends. A handler with no destination filters (returns None); one destination returns a
    # single Send; several return a list of Sends.
    if not h.destinations:
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

    channels = parse_export(text)
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
        unmapped_classes: list[str] = []
        for h in ch.handlers:
            for step in h.steps:
                if isinstance(step, Action):
                    mapped += 1
                else:
                    unmapped_classes.append(step.source_class)
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
            )
        )
    return ImportResult(tuple(results))


# --- rendering + validation helpers ------------------------------------------


def _lit(value: Any) -> str:
    """Render ``value`` as a SAFE Python literal via :func:`json.dumps`.

    ``json.dumps`` emits a fully-escaped double-quoted string / list / dict literal that is also valid
    Python source, so an untrusted export value (even one containing quotes, backslashes, or newlines)
    rides across as inert data and cannot break out of the literal to inject code (CLAUDE.md §5/§8)."""
    return json.dumps(value)


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
