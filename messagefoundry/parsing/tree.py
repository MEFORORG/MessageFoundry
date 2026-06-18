# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Structured HL7 parse tree for the message viewer.

Turns a raw message into a nested ``segment → field → repetition → component →
subcomponent`` structure with HL7 paths and values, so the console can render an
explorable tree without reaching into ``python-hl7`` internals. Pure and tolerant: it
builds whatever parses (the viewer must show non-conformant messages too).

Splitting is done from the message's own MSH-1/MSH-2 separators rather than assumed
defaults, so messages using non-standard encoding characters render correctly. MSH-1
(the field separator) and MSH-2 (the encoding characters) are represented as literal
single-value fields, matching how operators expect to see them.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from messagefoundry.parsing.peek import (
    DEFAULT_MAX_MESSAGE_BYTES,
    DEFAULT_MAX_SEGMENTS,
    HL7PeekError,
    enforce_size_limits,
    normalize,
)

__all__ = ["TreeNode", "parse_tree"]


@dataclass
class TreeNode:
    """One node in the parse tree.

    ``label`` is a human/HL7 label (``MSH``, ``MSH-9``, ``MSH-9.1`` …); ``value`` is the
    raw text of that node (empty for nodes that only group children); ``children`` are the
    next level down. Leaf nodes (subcomponents, or atomic components/fields) have no
    children and carry the value."""

    label: str
    value: str = ""
    children: list["TreeNode"] = field(default_factory=list)


def parse_tree(raw: str | bytes) -> list[TreeNode]:
    """Build a list of segment :class:`TreeNode` from ``raw``.

    Raises :class:`HL7PeekError` only when there is no parseable MSH to derive separators
    from; otherwise it returns the best-effort structure of whatever is present.
    """
    text = normalize(raw).strip("\r")
    if not text:
        raise HL7PeekError("empty message")
    enforce_size_limits(
        text, max_bytes=DEFAULT_MAX_MESSAGE_BYTES, max_segments=DEFAULT_MAX_SEGMENTS
    )
    segments = [s for s in text.split("\r") if s]
    if not segments or not segments[0].startswith("MSH"):
        raise HL7PeekError("message does not start with an MSH segment")

    field_sep, comp_sep, rep_sep, sub_sep = _separators(segments[0])
    return [_segment_node(seg, field_sep, comp_sep, rep_sep, sub_sep) for seg in segments]


def _separators(msh: str) -> tuple[str, str, str, str]:
    """Derive (field, component, repetition, subcomponent) separators from the MSH line."""
    field_sep = msh[3] if len(msh) > 3 else "|"
    enc = msh[4:8] if len(msh) > 4 else "^~\\&"
    comp_sep = enc[0] if len(enc) > 0 else "^"
    rep_sep = enc[1] if len(enc) > 1 else "~"
    sub_sep = enc[3] if len(enc) > 3 else "&"
    return field_sep, comp_sep, rep_sep, sub_sep


def _segment_node(
    segment: str, field_sep: str, comp_sep: str, rep_sep: str, sub_sep: str
) -> TreeNode:
    parts = segment.split(field_sep)
    seg_id = parts[0]
    node = TreeNode(label=seg_id)

    if seg_id == "MSH":
        # MSH-1 is the field separator itself; MSH-2 the encoding chars. Render them as
        # literal fields and number the rest from 3 so paths line up with the spec.
        node.children.append(TreeNode(label="MSH-1", value=field_sep))
        if len(parts) > 1:
            node.children.append(TreeNode(label="MSH-2", value=parts[1]))
        raw_fields = parts[2:]
        start_index = 3
    else:
        raw_fields = parts[1:]
        start_index = 1

    for offset, raw_field in enumerate(raw_fields):
        fld_index = start_index + offset
        node.children.append(
            _field_node(f"{seg_id}-{fld_index}", raw_field, comp_sep, rep_sep, sub_sep)
        )
    return node


def _field_node(label: str, raw_field: str, comp_sep: str, rep_sep: str, sub_sep: str) -> TreeNode:
    repetitions = raw_field.split(rep_sep)
    if len(repetitions) > 1:
        node = TreeNode(label=label, value=raw_field)
        for i, rep in enumerate(repetitions, start=1):
            node.children.append(_components_node(f"{label}[{i}]", rep, comp_sep, sub_sep))
        return node
    return _components_node(label, raw_field, comp_sep, sub_sep)


def _components_node(label: str, raw_value: str, comp_sep: str, sub_sep: str) -> TreeNode:
    components = raw_value.split(comp_sep)
    if len(components) <= 1 and sub_sep not in raw_value:
        # Atomic field/repetition: a single leaf carrying the value. (A lone component
        # that itself has subcomponents, e.g. ``a&b&c``, still expands below.)
        return TreeNode(label=label, value=raw_value)
    node = TreeNode(label=label, value=raw_value)
    for ci, comp in enumerate(components, start=1):
        subs = comp.split(sub_sep)
        if len(subs) <= 1:
            node.children.append(TreeNode(label=f"{label}.{ci}", value=comp))
        else:
            comp_node = TreeNode(label=f"{label}.{ci}", value=comp)
            for si, sub in enumerate(subs, start=1):
                comp_node.children.append(TreeNode(label=f"{label}.{ci}.{si}", value=sub))
            node.children.append(comp_node)
    return node
