# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Structured HL7 parse tree for the message viewer.

Turns a raw message into a nested ``segment → field → repetition → component →
subcomponent`` structure with HL7 paths and values, so the console can render an
explorable tree without reaching into the parser's internals. Pure and tolerant: it
builds whatever parses (the viewer must show non-conformant messages too).

Splitting is done from the message's own MSH-1/MSH-2 separators rather than assumed
defaults, so messages using non-standard encoding characters render correctly. MSH-1
(the field separator) and MSH-2 (the encoding characters) are represented as literal
single-value fields, matching how operators expect to see them.

The tree is bounded by :data:`MAX_TREE_NODES` and :data:`MAX_TREE_VALUE_CHARS`. The byte and segment
caps do not bound it: one field made of component separators is one segment and a few bytes per
node, so a body under the 16 MiB cap could otherwise build millions of nodes; and each node carries
its own raw text, so one large field is held again at every level it nests (vault BACKLOG #2762).
Past either cap, or the byte and segment caps, :func:`parse_tree` raises
:class:`ParseTreeTooLargeError` instead of building on.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from messagefoundry.parsing._builtin_hl7 import _extract_separators
from messagefoundry.parsing.peek import (
    DEFAULT_MAX_MESSAGE_BYTES,
    DEFAULT_MAX_SEGMENTS,
    HL7PeekError,
    enforce_size_limits,
    normalize,
)

__all__ = [
    "MAX_TREE_NODES",
    "MAX_TREE_VALUE_CHARS",
    "ParseTreeTooLargeError",
    "TreeNode",
    "parse_tree",
]

#: The most nodes :func:`parse_tree` builds for one message. 2,000 segments of 20 simple fields is
#: about 42,000 nodes; a message near the 10,000-segment cap can pass it, and gets the raw view. At
#: the cap the tree builds in a fraction of a second and renders in under one (measured 2026-10-06),
#: and a page of this many list items is already past what an operator can read.
MAX_TREE_NODES = 100_000

#: The most characters of node labels and values the tree holds. A node keeps its own raw text, so
#: one field is held again as its repetition, component and subcomponent, and every label repeats
#: the segment id, whose length nothing else bounds: a body of a few large fields, or one long
#: segment id over many fields, stays under :data:`MAX_TREE_NODES` and still builds and renders many
#: times its own size. An embedded document of up to about 2 MiB in one OBX-5 fits, held twice. The
#: worst case at the cap, every character one that HTML escapes to five (``"``), rendered about
#: 24 MB of page in under two seconds (measured 2026-10-06, off the event loop).
MAX_TREE_VALUE_CHARS = 4 * 1024 * 1024


class ParseTreeTooLargeError(HL7PeekError):
    """The message is too large to render as a tree: past a tree cap, or the byte or segment cap.
    A subclass of :class:`HL7PeekError` so a caller that only knows that error still degrades to
    "no tree". The text carries limits and counts only, never message content."""


@dataclass
class TreeNode:
    """One node in the parse tree.

    ``label`` is a human/HL7 label (``MSH``, ``MSH-9``, ``MSH-9.1`` …); ``value`` is the
    raw text of that node (empty for nodes that only group children); ``children`` are the
    next level down. Leaf nodes (subcomponents, or atomic components/fields) have no
    children and carry the value."""

    label: str
    value: str = ""
    children: list[TreeNode] = field(default_factory=list)


def parse_tree(
    raw: str | bytes,
    *,
    max_nodes: int = MAX_TREE_NODES,
    max_value_chars: int = MAX_TREE_VALUE_CHARS,
) -> list[TreeNode]:
    """Build a list of segment :class:`TreeNode` from ``raw``.

    Raises :class:`HL7PeekError` only when there is no parseable MSH to derive separators
    from, and its subclass :class:`ParseTreeTooLargeError` when the message is too large to
    render; otherwise it returns the best-effort structure of whatever is present.
    """
    text = normalize(raw).strip("\r")
    if not text:
        raise HL7PeekError("empty message")
    # Before the size checks, so a large non-HL7 body reads as "not HL7" rather than "too large".
    if not text.startswith("MSH"):
        raise HL7PeekError("message does not start with an MSH segment")
    # Keep only the refusal's text (limits and counts, never content) and raise after the handler
    # ends, so the new error carries no __cause__ or __context__ holding the body.
    too_large: str | None = None
    try:
        enforce_size_limits(
            text, max_bytes=DEFAULT_MAX_MESSAGE_BYTES, max_segments=DEFAULT_MAX_SEGMENTS
        )
    except HL7PeekError as exc:
        too_large = str(exc)
    if too_large is not None:
        raise ParseTreeTooLargeError(too_large)
    segments = [s for s in text.split("\r") if s]

    builder = _TreeBuilder(_separators(segments[0]), max_nodes, max_value_chars)
    return [builder.segment(seg) for seg in segments]


def _separators(msh: str) -> tuple[str, str, str, str]:
    """Derive (field, component, repetition, subcomponent) separators from the MSH line.

    Read the way the parser reads them (:func:`_extract_separators`): MSH-2 ends at the next field
    separator, so ``MSH|^~|A`` declares only a component and a repetition separator and ``A`` is
    MSH-3. A fixed ``msh[4:8]`` slice took ``A`` as the subcomponent separator there. A header too
    short for the parser to read keeps the defaults, so the viewer still shows it."""
    if len(msh) < 5:
        return (msh[3] if len(msh) > 3 else "|"), "^", "~", "&"
    field_sep, comp_sep, rep_sep, sub_sep, _escape = _extract_separators(msh)
    return field_sep, comp_sep, rep_sep, sub_sep


class _TreeBuilder:
    """Builds the nodes for one message, counting nodes and value characters against the caps.

    Every node is counted as it is made, and every split is checked first: a split into more parts
    than the nodes left would pass the cap whatever follows, so it is refused before the list of
    parts is allocated."""

    def __init__(
        self, separators: tuple[str, str, str, str], max_nodes: int, max_value_chars: int
    ) -> None:
        self._field_sep, self._comp_sep, self._rep_sep, self._sub_sep = separators
        self._max_nodes = max_nodes
        self._max_value_chars = max_value_chars
        self._nodes_left = max_nodes
        self._chars_left = max_value_chars

    def _too_many_nodes(self) -> ParseTreeTooLargeError:
        return ParseTreeTooLargeError(
            f"the parse tree is too large to render (more than {self._max_nodes:,} nodes)"
        )

    def _node(self, label: str, value: str = "") -> TreeNode:
        self._nodes_left -= 1
        self._chars_left -= len(label) + len(value)
        if self._nodes_left < 0:
            raise self._too_many_nodes()
        if self._chars_left < 0:
            raise ParseTreeTooLargeError(
                "the parse tree is too large to render (more than "
                f"{self._max_value_chars:,} characters of labels and values)"
            )
        return TreeNode(label=label, value=value)

    def _split(self, value: str, sep: str) -> list[str]:
        # A split into count + 1 parts builds at least count + 1 nodes (the node that holds the
        # value, or the segment node for a segment's id), so this refuses only what must exceed.
        if value.count(sep) >= self._nodes_left:
            raise self._too_many_nodes()
        return value.split(sep)

    def segment(self, segment: str) -> TreeNode:
        parts = self._split(segment, self._field_sep)
        seg_id = parts[0]
        node = self._node(seg_id)

        if seg_id == "MSH":
            # MSH-1 is the field separator itself; MSH-2 the encoding chars. Render them as
            # literal fields and number the rest from 3 so paths line up with the spec.
            node.children.append(self._node("MSH-1", self._field_sep))
            if len(parts) > 1:
                node.children.append(self._node("MSH-2", parts[1]))
            raw_fields = parts[2:]
            start_index = 3
        else:
            raw_fields = parts[1:]
            start_index = 1

        for offset, raw_field in enumerate(raw_fields):
            node.children.append(self._field(f"{seg_id}-{start_index + offset}", raw_field))
        return node

    def _field(self, label: str, raw_field: str) -> TreeNode:
        repetitions = self._split(raw_field, self._rep_sep)
        if len(repetitions) > 1:
            node = self._node(label, raw_field)
            for i, rep in enumerate(repetitions, start=1):
                node.children.append(self._components(f"{label}[{i}]", rep))
            return node
        return self._components(label, raw_field)

    def _components(self, label: str, raw_value: str) -> TreeNode:
        components = self._split(raw_value, self._comp_sep)
        if len(components) <= 1 and self._sub_sep not in raw_value:
            # Atomic field/repetition: a single leaf carrying the value. (A lone component
            # that itself has subcomponents, e.g. ``a&b&c``, still expands below.)
            return self._node(label, raw_value)
        node = self._node(label, raw_value)
        for ci, comp in enumerate(components, start=1):
            subs = self._split(comp, self._sub_sep)
            comp_node = self._node(f"{label}.{ci}", comp)
            if len(subs) > 1:
                for si, sub in enumerate(subs, start=1):
                    comp_node.children.append(self._node(f"{label}.{ci}.{si}", sub))
            node.children.append(comp_node)
        return node
