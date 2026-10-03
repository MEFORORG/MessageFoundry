# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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
of concatenated HL7 (split on ``MSH`` boundaries) — so the same loader takes both sides. Each file is
read bounded (ASVS 5.1.1): at most ``max_file_bytes``, default :data:`DEFAULT_MAX_LOAD_FILE_BYTES`,
through :func:`harness.bounded_file.read_capped`; a file over it, or a named path that is not a regular
file, is refused with :class:`LoadError` naming the file, never read whole. ``python -m
harness.reconcile compare --max-file-bytes`` changes the cap.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from harness.bounded_file import NOT_REGULAR, read_capped
from harness.reconcile.normalize import (
    Difference,
    NormalizeRules,
    ReconcileError,
    Separators,
    diff,
)
from messagefoundry.parsing.peek import DEFAULT_MAX_MESSAGE_BYTES
from messagefoundry.parsing.peek import normalize as _normalize_line_endings
from messagefoundry.redaction import json_loads_or_refusal

_log = logging.getLogger(__name__)

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


#: The largest input file :func:`load_messages` reads. A capture or an export holds many messages and
#: is held in memory whole, so this is a file bound, not the engine's per-message cap: 64 of those,
#: 1 GiB. ``python -m harness.reconcile compare --max-file-bytes`` changes it.
DEFAULT_MAX_LOAD_FILE_BYTES = 64 * DEFAULT_MAX_MESSAGE_BYTES


class LoadError(ValueError):
    """An input :func:`load_messages` refused: a file over the cap or not a regular file, or a JSONL
    line that is not a capture record. ``over_cap`` says which, so a caller can name the setting that
    would help. The message names the path and, for a line, its number; it never quotes content, so
    a caller may print it."""

    def __init__(self, message: str, *, over_cap: bool) -> None:
        super().__init__(message)
        self.over_cap = over_cap


def _read(path: Path, cap: int) -> bytes:
    """``path``'s bytes, bounded. A missing or unreadable file raises ``OSError`` as it always did."""
    data, reason = read_capped(path, cap)
    if reason:
        raise LoadError(f"{path}: {reason}", over_cap=reason != NOT_REGULAR)
    return data


#: One JSONL line and its break. A record's JSON cannot hold a raw CR or LF, so these are the only
#: breaks; str.splitlines() would also split on U+0085 and U+2028, which the capture sink writes raw
#: (``ensure_ascii=False``). Matched lazily, so a 1 GiB capture is not copied into a list of lines.
_JSONL_LINE = re.compile(r"[^\r\n]*(?:\r\n|\r|\n)|[^\r\n]+\Z")


def _record(path: Path, number: int, line: str) -> str:
    """The ``raw`` of one JSONL capture line, or :class:`LoadError` naming the line, never its text."""
    # Returns rather than raises, so the refusal below chains no decode error: a JSONDecodeError
    # carries the whole line in ``.doc``, and ``from None`` would still leave it on ``__context__``.
    record, refusal = json_loads_or_refusal(line)
    if refusal is not None:
        raise LoadError(f"{path}: line {number} is not valid JSON", over_cap=False)
    raw = record.get("raw") if isinstance(record, dict) else None
    if not isinstance(raw, str):
        # A list or a number here used to raise TypeError, which the CLI did not catch, so it exited
        # 1, the code for "the outputs differ".
        raise LoadError(
            f"{path}: line {number} is not an object with a string 'raw'", over_cap=False
        )
    return raw


def _parse(path: Path, data: bytes) -> list[str]:
    """The messages in one file's bytes: a JSONL capture by its ``.jsonl`` name, else HL7."""
    if path.suffix != ".jsonl":
        return _split_batch(data.decode("latin-1"))
    # utf-8-sig drops a byte-order mark, which some Windows tools write before UTF-8 text.
    text = data.decode("utf-8-sig")
    msgs: list[str] = []
    for number, match in enumerate(_JSONL_LINE.finditer(text), 1):
        line = match.group().strip()
        if line:
            msgs.append(_record(path, number, line))
    return msgs


def load_messages(
    path: str | Path, *, max_file_bytes: int = DEFAULT_MAX_LOAD_FILE_BYTES
) -> list[str]:
    """Load raw HL7 messages from a MEFOR JSONL capture, a directory of one-message files, or a single
    batch file of concatenated messages (split on ``MSH`` line boundaries). A file named ``*.jsonl``,
    named or in a directory, is read as a capture; any other is read as HL7.

    Each file is capped at ``max_file_bytes`` (default :data:`DEFAULT_MAX_LOAD_FILE_BYTES`) and refused
    with :class:`LoadError` over it, before it is read whole; so is a named path that is not a regular
    file, and a JSONL line that is not an object with a string ``raw``. In a directory the cap is a
    TOTAL across its files, since every message is held at once. Only regular files in it are read: a
    symlink is not followed, as in the File tab's watch pane, and it, anything else that is not a
    regular file, or an entry gone before it is read is skipped, with a warning that counts the skips."""
    if max_file_bytes <= 0:
        raise ValueError(f"max_file_bytes must be a positive byte count, got {max_file_bytes}")
    p = Path(path)
    if not p.is_dir():
        return _parse(p, _read(p, max_file_bytes))
    out: list[str] = []
    left = max_file_bytes
    skipped = 0
    for child in sorted(p.iterdir()):
        # The directory's entries are another system's output, not paths the operator named, so a
        # symlink among them is not followed: it could point anywhere the operator can read.
        try:
            data, reason = read_capped(child, left, follow_symlinks=False)
        except FileNotFoundError:
            reason = NOT_REGULAR  # removed since the listing, as a writer's temp file can be
        if reason == NOT_REGULAR:
            skipped += 1
            continue
        if reason:
            # The cap passed was what is left of the directory's total, so say so beside it.
            raise LoadError(
                f"{child}: {reason}; in a directory that cap is what was left of the "
                f"{max_file_bytes}-byte total across its files",
                over_cap=True,
            )
        left -= len(data)
        out.extend(_parse(child, data))
    if skipped:
        # A skip is silent in the result, and a key it hides reads as a one-sided difference.
        _log.warning(
            "%s: skipped %d %s not a regular file (a symlink is not followed)",
            p,
            skipped,
            "entry that is" if skipped == 1 else "entries that are",
        )
    return out


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
