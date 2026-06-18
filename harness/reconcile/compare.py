# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Per-connection offline reconciliation: match MEFOR's captured output against Corepoint's export and
diff each pair with the normalize core (TEST-ENVIRONMENT-PLAN.md §5).

The two sides are processed from the *same* inbound messages, so each output carries a correlating id;
they are paired on a **configurable match key** (default ``MSH-10`` — many feeds preserve the inbound
control id there; an operator points it at a stable order/placer field per connection when the engines
regenerate ``MSH-10``). Matched pairs are diffed via :func:`harness.reconcile.normalize.diff` (which
blanks the engine-non-deterministic fields); unmatched ids on either side are surfaced as findings too
(MEFOR produced an output Corepoint didn't, or vice-versa).

Inputs are read by :func:`load_messages`, which accepts a MEFOR JSONL capture (from
:class:`harness.reconcile.capture.CaptureSink`), a directory of one-message files, or a single batch file
of concatenated HL7 (split on ``MSH`` boundaries) — so the same loader takes both sides.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from messagefoundry.parsing.peek import normalize as _normalize_line_endings

from harness.reconcile.normalize import (
    Difference,
    NormalizeRules,
    ReconcileError,
    Separators,
    diff,
)

#: Default per-connection match key — the message control id (``MSH-10``).
DEFAULT_KEY: tuple[str, int] = ("MSH", 10)


def field_value(raw: str, key: tuple[str, int]) -> str | None:
    """Read ``(segment_id, field_no)`` from a raw HL7 message on its own declared separators (read-only;
    never slices to mutate). Returns ``None`` if the segment/field is absent. ``MSH-1`` is the field
    separator, so an ``MSH`` field ``N`` is at split index ``N-1``; every other segment's is at ``N``."""
    seg_id, field_no = key
    sep = Separators.from_message(raw)  # raises ReconcileError if there's no MSH header
    for line in _normalize_line_endings(raw).split("\r"):
        if not line.strip():
            continue
        fields = line.split(sep.field)
        if fields and fields[0] == seg_id:
            idx = field_no - 1 if seg_id == "MSH" else field_no
            return fields[idx] if 0 <= idx < len(fields) else None
    return None


def load_messages(path: str | Path) -> list[str]:
    """Load raw HL7 messages from a MEFOR JSONL capture, a directory of one-message files, or a single
    batch file of concatenated messages (split on ``MSH`` line boundaries)."""
    p = Path(path)
    if p.is_dir():
        out: list[str] = []
        for child in sorted(p.iterdir()):
            if child.is_file():
                out.extend(_split_batch(child.read_text(encoding="latin-1")))
        return out
    text = p.read_text(encoding="utf-8" if p.suffix == ".jsonl" else "latin-1")
    if p.suffix == ".jsonl":
        msgs: list[str] = []
        for line in text.splitlines():
            line = line.strip()
            if line:
                msgs.append(json.loads(line)["raw"])
        return msgs
    return _split_batch(text)


def _split_batch(text: str) -> list[str]:
    """Split concatenated HL7 into messages: each ``MSH`` line starts a new one (MLLP wrappers, if any,
    are tolerated since we key off the ``MSH`` prefix of a stripped line)."""
    norm = _normalize_line_endings(text)
    msgs: list[str] = []
    current: list[str] = []
    for line in norm.split("\r"):
        if line.lstrip("\x0b").startswith("MSH"):
            if current:
                msgs.append("\r".join(current))
            current = [line.lstrip("\x0b")]
        elif current:
            stripped = line.rstrip("\x1c\x0d")
            if stripped:
                current.append(stripped)
    if current:
        msgs.append("\r".join(current))
    return msgs


@dataclass(frozen=True)
class MessagePair:
    """One matched (key) pair and the real differences between MEFOR's and Corepoint's output."""

    key: str
    differences: list[Difference]

    @property
    def matches(self) -> bool:
        return not self.differences


@dataclass
class ReconcileResult:
    """The per-connection reconciliation outcome."""

    connection: str
    pairs: list[MessagePair] = field(default_factory=list)
    mefor_only: list[str] = field(default_factory=list)  # keys MEFOR produced but Corepoint didn't
    corepoint_only: list[str] = field(
        default_factory=list
    )  # keys Corepoint produced but MEFOR didn't
    unkeyed_mefor: int = 0  # MEFOR messages with no extractable key (excluded from pairing)
    unkeyed_corepoint: int = 0
    duplicate_keys: list[str] = field(default_factory=list)  # key seen >1x on a side (last wins)

    @property
    def mismatched(self) -> list[MessagePair]:
        return [p for p in self.pairs if not p.matches]

    @property
    def clean(self) -> bool:
        """True iff every matched pair is identical and nothing is unmatched on either side."""
        return (
            not self.mismatched
            and not self.mefor_only
            and not self.corepoint_only
            and not self.unkeyed_mefor
            and not self.unkeyed_corepoint
        )


def _index(messages: list[str], key: tuple[str, int]) -> tuple[dict[str, str], int, list[str]]:
    """Index messages by their extracted key. Returns (key→raw, unkeyed_count, duplicate_keys)."""
    by_key: dict[str, str] = {}
    dupes: list[str] = []
    unkeyed = 0
    for raw in messages:
        try:
            k = field_value(raw, key)
        except ReconcileError:
            unkeyed += 1
            continue
        if not k:
            unkeyed += 1
            continue
        if k in by_key:
            dupes.append(k)
        by_key[k] = raw  # last occurrence wins (dupes recorded as a finding)
    return by_key, unkeyed, dupes


def reconcile(
    mefor: list[str],
    corepoint: list[str],
    *,
    connection: str = "<connection>",
    key: tuple[str, int] = DEFAULT_KEY,
    rules: NormalizeRules | None = None,
) -> ReconcileResult:
    """Pair MEFOR's outputs with Corepoint's by ``key`` and diff each pair under ``rules``."""
    rules = rules or NormalizeRules()
    m_idx, m_unkeyed, m_dupes = _index(mefor, key)
    c_idx, c_unkeyed, c_dupes = _index(corepoint, key)
    result = ReconcileResult(
        connection=connection,
        unkeyed_mefor=m_unkeyed,
        unkeyed_corepoint=c_unkeyed,
        duplicate_keys=sorted(set(m_dupes) | set(c_dupes)),
        mefor_only=sorted(set(m_idx) - set(c_idx)),
        corepoint_only=sorted(set(c_idx) - set(m_idx)),
    )
    for k in sorted(set(m_idx) & set(c_idx)):
        result.pairs.append(MessagePair(key=k, differences=diff(m_idx[k], c_idx[k], rules)))
    return result
