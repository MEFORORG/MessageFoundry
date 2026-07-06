# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Low-allocation built-ins HL7 v2 parser (ADR 0054) — the python-hl7 drop-in.

This module reimplements python-hl7's *tolerant* parse over native ``dict``/``list``/``str``
with **no per-node custom classes**, so the parsed representation stops contending under
free-threading (ADR 0053 WS3: per-instance refcounting + shared type objects serialize across
threads). It backs the existing :class:`~messagefoundry.parsing.peek.Peek` and
:class:`~messagefoundry.parsing.message.Message` API **byte-for-byte** — see the ADR's preserved
contract. It is **pure** (no I/O, engine state, or DB) and has **no public exports yet**;
``peek.py``/``message.py`` switch to it in a later phase.

Data model (a plain built-in structure)::

    ParsedMessage = {
        "segments": [ {"id": str, "fields": list[str | dict]}, ... ],
        "raw": str | None,           # cached encode; None once dirtied
        "seps": (field, component, repetition, subcomponent, escape),
    }

A *field entry* is the **raw repetition text** (``str``) until first componentized access; on the
first component/subcomponent read it is split on the message's own separators and the breakdown
cached in the entry as a ``dict`` (``{"text": str, "reps": list[list[list[str]]]}``). Component-less
fields stay bare strings — the same "rep is ``str`` vs structured" branch python-hl7 makes.

**MSH is parsed eagerly** (its MSH-1/MSH-2 give the separators every other split needs); **all other
segments are stored as raw text and split lazily on first field-path touch, then cached.** ``encode``
rebuilds the ``\\r``-delimited raw by joining on the actual separators **only when dirty**, else
returns the cached raw.

The semantics here mirror two *distinct* python-hl7 surfaces the existing code relies on:

* :func:`extract_field` — python-hl7's ``Segment.extract_field`` (what ``Peek`` uses). When the parse
  tree is **deeper** than the requested path it follows the first child to a leaf; a component read of
  a field with no component separator returns the **whole** value (the ``ORC-2.1`` of ``PLACER123`` →
  ``PLACER123`` rule), and the out-of-range **asymmetry** holds (valid over-index → ``""``;
  invalid-depth → ``IndexError``).
* :func:`extract_part` — the string-level component/subcomponent split ``Message`` uses (split only to
  the requested depth, never following first-children past it). These two **diverge** on a
  subcomponent-only field (``a&b`` at ``-1.1``: ``extract_field`` → ``a``; ``extract_part`` → ``a&b``),
  and both are preserved exactly.
"""

from __future__ import annotations

from typing import TypedDict

import hl7  # for byte-parity error types (ParseException) on the no-MSH-leading path

__all__ = [
    "ParsedMessage",
    "FieldEntry",
    "parse",
    "extract_field",
    "extract_part",
    "raw_field",
    "set_field",
    "encode",
    "segment_ids",
    "separators",
    "unescape",
    "escape_leaf",
    "raise_if_blank_segment_scan",
    "scan_segment_index",
]


class FieldEntry(TypedDict):
    """A componentized field entry (the cached breakdown of a field's raw text).

    ``text`` is the field's full raw text (every repetition); ``reps`` is the lazily-built
    ``repetition → component → subcomponent`` split of it on the message's own separators. A field
    is stored as a bare ``str`` until first component/subcomponent access, at which point this dict
    replaces it in ``fields`` and caches the split.
    """

    text: str
    reps: list[list[list[str]]]


class Segment(TypedDict):
    """One parsed segment: its id (``""`` for an empty/blank line) and its field entries.

    For a non-MSH segment, ``fields`` is populated **lazily** — it starts empty while the raw segment
    line waits in :data:`ParsedMessage`'s ``_lazy`` map, and is split into bare-``str`` field entries on
    first field touch (see :func:`_ensure_split`). MSH is split eagerly and never lazy.
    """

    id: str
    fields: list[str | FieldEntry]


class ParsedMessage(TypedDict):
    """The whole parsed message — see the module docstring for the shape."""

    segments: list[Segment]
    raw: str | None
    seps: tuple[str, str, str, str, str]
    # Per-segment raw text awaiting a lazy split (index in ``segments`` → raw line). MSH is never
    # here (parsed eagerly). A segment leaves this map the first time a field path touches it.
    _lazy: dict[int, str]


# ---------------------------------------------------------------------------
# Parse
# ---------------------------------------------------------------------------


def _extract_separators(msh_line: str) -> tuple[str, str, str, str, str]:
    """Read ``(field, component, repetition, subcomponent, escape)`` from an MSH/BHS/FHS line.

    Replicates ``hl7.create_parse_plan`` exactly: ``sep0 = line[3]``; the encoding chars are
    ``line[3:line.find(sep0, 4)]`` (note python-hl7's ``find`` may return ``-1`` on a malformed MSH-2,
    slicing to ``[:-1]`` — that quirk is preserved for byte-parity). Defaults fill any missing slot:
    repetition ``~``, component ``^``, subcomponent ``&``, escape ``\\``.
    """
    sep0 = msh_line[3]
    seps = list(msh_line[3 : msh_line.find(sep0, 4)])
    field = seps[0]
    component = seps[1] if len(seps) > 1 else "^"
    repetition = seps[2] if len(seps) > 2 else "~"
    escape = seps[3] if len(seps) > 3 else "\\"
    subcomponent = seps[4] if len(seps) > 4 else "&"
    return field, component, repetition, subcomponent, escape


def _parse_msh(msh_line: str, seps: tuple[str, str, str, str, str]) -> Segment:
    """Eagerly split the MSH/BHS/FHS line into field entries, hiding the separator offset.

    Mirrors ``hl7._split``'s special-casing: field 0 = the segment id, field 1 = the field separator
    char (MSH-1, returned raw), field 2 = the encoding-characters string (MSH-2, returned raw), and
    the *rest* come from splitting the remainder on the field separator. So ``fields[1]`` is MSH-1,
    ``fields[2]`` is MSH-2, ``fields[3]`` is the first real field (MSH-3).
    """
    field_sep = seps[0]
    sep0 = msh_line[3]
    sep_end = msh_line.find(sep0, 4)
    enc_chars = msh_line[4:sep_end]
    rest = msh_line[sep_end + 1 :]
    fields: list[str | FieldEntry] = [msh_line[:3], sep0, enc_chars]
    if rest:
        fields.extend(rest.split(field_sep))
    return {"id": msh_line[:3], "fields": fields}


def parse(norm: str) -> ParsedMessage:
    """Parse a ``\\r``-normalized HL7 string into a :class:`ParsedMessage`.

    ``norm`` is expected already normalized (line endings collapsed to ``\\r``); this mirrors
    ``hl7.parse`` by stripping surrounding whitespace, then splitting segments on ``\\r``. MSH is
    parsed eagerly (its separators are needed for everything else); other segments are stored raw and
    split lazily.

    Like ``hl7.create_parse_plan`` it enforces an **MSH/FHS/BHS leading segment**, raising
    :class:`hl7.exceptions.ParseException` (the same type python-hl7 raises) when the first segment is
    anything else — so a non-HL7 body fed straight to :meth:`Message.parse` (which, unlike
    ``Peek.parse``, has no pre-parse no-MSH guard) is rejected identically instead of silently parsed
    with garbage separators read from arbitrary leading text.
    """
    strmsg = norm.strip()
    lines = strmsg.split("\r")
    if lines[0][:3] not in ("MSH", "FHS", "BHS"):
        # python-hl7's wording (note its literal "MHS" typo in the allowed list is reproduced for the
        # message text; the parity suite compares exception *type*, not text).
        raise hl7.ParseException(f"First segment is {lines[0][:3]}, must be one of MHS, FHS or BHS")
    seps = _extract_separators(lines[0])

    field_sep = seps[0]
    segments: list[Segment] = []
    lazy: dict[int, str] = {}
    for index, line in enumerate(lines):
        if index == 0:
            # The first segment is MSH/BHS/FHS; split it eagerly off its own separators.
            segments.append(_parse_msh(line, seps))
            continue
        if line[:3] in ("MSH", "BHS", "FHS"):
            # A further header-style line (e.g. a stray MSH) also splits eagerly.
            segments.append(_parse_msh(line, seps))
            continue
        # The segment id is the token before the first field separator — python-hl7 derives it the
        # same way (``segment[0]`` after splitting the line on the field sep), so a non-3-char id
        # (e.g. ``PV``/``PIDX``/``NTEXY``/``Z``, a malformed feed) is filed under its real id instead of
        # the wrong ``line[:3]`` slice (which truncates/over-runs and can mis-collide with a real id).
        # An empty line (a blank segment from a ``\r\r``) has id ""; everything else defers its split.
        segments.append({"id": line.split(field_sep, 1)[0] if line else "", "fields": []})
        lazy[index] = line

    return {"segments": segments, "raw": strmsg + "\r", "seps": seps, "_lazy": lazy}


def _ensure_split(msg: ParsedMessage, seg_index: int) -> None:
    """Split a lazily-stored segment's raw line into bare field strings (idempotent).

    A non-MSH segment is split on the field separator the first time a field path touches it; the
    field entries start as bare ``str`` (component split is deferred again, per field, to first
    componentized access). MSH segments are never lazy.
    """
    raw = msg["_lazy"].pop(seg_index, None)
    if raw is None:
        return
    field_sep = msg["seps"][0]
    parts = raw.split(field_sep)
    # parts[0] is the segment id; fields are 1-based after it (matching python-hl7's Segment indexing
    # where index 0 is the id and field N is at list index N).
    msg["segments"][seg_index]["fields"] = list(parts)


def _segment_index(msg: ParsedMessage, seg_id: str, occurrence: int) -> int | None:
    """List index of the ``occurrence``-th (1-based) segment with ``seg_id``, or None if absent.

    Tolerant scan (mirrors python-hl7's ``Message._segment_obj`` / ``str(segment[0])`` iteration the
    legacy ``Message`` read+presence path uses): a blank segment is skipped, never an error. The
    *raising* scan python-hl7 does for ``segment()``/``extract_field``/whole-field assignment lives in
    :func:`raise_if_blank_segment_scan`.
    """
    seen = 0
    for i, seg in enumerate(msg["segments"]):
        if seg["id"] == seg_id:
            seen += 1
            if seen == occurrence:
                return i
    return None


def _is_fieldless(msg: ParsedMessage, seg_index: int) -> bool:
    """Whether a segment line carries **no field separator at all** (just a bare id like ``PID``).

    This is the distinction python-hl7's ``segments()`` matcher turns on (see
    :func:`scan_segment_index`): a fieldless line parses such that ``segment[0]`` is a plain ``str``
    (the id) rather than a ``Field``, so ``segment[0][0]`` is the id's first *character* — which never
    equals the id, so the segment is silently skipped by an id lookup. A line with even an empty
    trailing field (``PID|``) is *not* fieldless. Detected from the lazy raw line (no field sep) or,
    once split, a single field entry (only the id). MSH/BHS/FHS are always populated.
    """
    lazy_raw = msg["_lazy"].get(seg_index)
    if lazy_raw is not None:
        return msg["seps"][0] not in lazy_raw
    return len(msg["segments"][seg_index]["fields"]) <= 1


def raise_if_blank_segment_scan(msg: ParsedMessage) -> None:
    """Replicate python-hl7's ``Message.segments()`` blow-up on a blank/empty segment.

    python-hl7 resolves a segment by id with ``Sequence(seg for seg in self if seg[0][0] == id)``,
    which materializes ``seg[0][0]`` for **every** segment in the message — so an empty/blank segment
    (its first field is ``""``) makes ``""[0]`` raise ``IndexError('string index out of range')``,
    aborting the lookup **regardless of where the blank segment sits relative to the target**. Every
    by-id resolution that routes through that scan (``segment()``, ``extract_field``, whole-field
    assignment via ``msg["SEG.Fn"] = …``) therefore raises whenever the message carries any blank
    segment. The tolerant ``str(segment[0])`` iteration (reads, presence, occurrence>1 writes) does
    **not** — so this guard is invoked only on the raising paths to preserve that exact asymmetry.
    """
    for seg in msg["segments"]:
        if seg["id"] == "":
            raise IndexError("string index out of range")


def scan_segment_index(msg: ParsedMessage, seg_id: str, occurrence: int) -> int | None:
    """List index of the ``occurrence``-th id match using python-hl7's **``segments()`` matcher**.

    The raising by-id paths (``Peek.field`` → :func:`extract_field`, and whole-field assignment →
    :func:`set_field` at occurrence 1) resolve the segment through python-hl7's
    ``Sequence(seg for seg in self if seg[0][0] == id)`` — which (a) blows up on any blank segment
    (handled by :func:`raise_if_blank_segment_scan`, called first) and (b) **skips a fieldless bare
    segment** (``seg[0][0]`` is the id's first character, never the id) so it is not counted as an
    occurrence. So a bare ``PID`` directly before a populated ``PID`` makes the populated one
    occurrence 1, exactly as the legacy path selects it. The tolerant read/presence path keeps using
    :func:`_segment_index` (which counts the bare segment), preserving the legacy read↔extract split.
    """
    seen = 0
    for i, seg in enumerate(msg["segments"]):
        if seg["id"] == seg_id and not _is_fieldless(msg, i):
            seen += 1
            if seen == occurrence:
                return i
    return None


def _field_text(entry: str | FieldEntry) -> str:
    """The raw text of a field entry, whether it is still a bare ``str`` or a cached dict."""
    return entry if isinstance(entry, str) else entry["text"]


def _componentize(
    msg: ParsedMessage, seg_index: int, fld: int, seps: tuple[str, str, str, str, str]
) -> FieldEntry:
    """Materialize (and cache in place) the ``repetition → component → subcomponent`` breakdown of a
    field, replacing its bare-``str`` entry with a :class:`FieldEntry` dict on first componentized
    access (the ADR data model's lazy field split).

    The caller has already ensured the segment is split and ``fld`` is in range. The cached ``reps``
    are a structural mirror of the raw ``text``; ``text`` stays authoritative (writes update it and
    drop the cache by re-assigning a bare ``str``), so the cache is only ever a read accelerator.
    """
    fields = msg["segments"][seg_index]["fields"]
    entry = fields[fld]
    if isinstance(entry, dict):
        return entry
    cached: FieldEntry = {"text": entry, "reps": _split_reps(entry, seps)}
    fields[fld] = cached
    return cached


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------


def raw_field(msg: ParsedMessage, seg_id: str, fld: int, occurrence: int = 1) -> str:
    """Raw text of ``seg_id``-``fld`` (1-based field) for the ``occurrence``-th segment.

    ``""`` if the segment occurrence or field is absent. For MSH this returns MSH-1/MSH-2 raw (the
    encoding chars), matching the hidden-offset model. This is the whole-field structural text — with
    any repetition delimiters — and is **not** unescaped (it is the inverse input to ``encode``).
    """
    seg_index = _segment_index(msg, seg_id, occurrence)
    if seg_index is None:
        return ""
    _ensure_split(msg, seg_index)
    fields = msg["segments"][seg_index]["fields"]
    if fld < len(fields):
        return _field_text(fields[fld])
    return ""


def _split_reps(text: str, seps: tuple[str, str, str, str, str]) -> list[list[list[str]]]:
    """Split a field's raw text into ``repetition → component → subcomponent`` lists."""
    _field, comp_sep, rep_sep, sub_sep, _esc = seps
    return [[comp.split(sub_sep) for comp in rep.split(comp_sep)] for rep in text.split(rep_sep)]


def extract_field(
    msg: ParsedMessage,
    seg_id: str,
    fld: int,
    comp: int | None,
    sub: int | None,
    *,
    occurrence: int = 1,
    repetition: int = 1,
) -> str | None:
    """Resolve a field path the way python-hl7's ``Segment.extract_field`` does (the ``Peek`` path).

    Returns the value at ``(seg, fld, repetition, comp, sub)`` — first occurrence/first repetition by
    default. ``comp is None`` → whole-field structural text (with repetition delimiters), ``""`` → None.
    A component/subcomponent read returns the **unescaped** leaf, with these python-hl7 rules preserved
    exactly:

    * **whole-value-no-component:** a field with no component separator returns the whole value
      (``ORC-2.1`` of ``PLACER123`` → ``PLACER123``), because the tree terminates at a leaf before the
      requested depth and python-hl7 returns that leaf when the remaining path is all-1s.
    * **first-child descent:** when the tree is deeper than the path, follow the first child to a leaf.
    * **out-of-range asymmetry:** a valid-structure over-index returns ``""`` (→ None); an
      invalid-depth index (a component/sub past a leaf) raises ``IndexError``.

    Raises ``IndexError`` for the invalid-depth case (surfaced as None at the Peek layer); returns None
    for absent/empty. Also raises ``IndexError`` when the message carries a blank segment — python-hl7's
    ``extract_field`` resolves the segment through the raising ``segments()`` scan
    (:func:`raise_if_blank_segment_scan`), so byte-parity requires the same blow-up here. The Peek layer
    runs that scan *before* its invalid-depth ``IndexError``→None catch, so a blank-segment error
    propagates while an over-index still maps to None (matching the legacy path's two separate catches).
    """
    raise_if_blank_segment_scan(msg)
    # python-hl7's ``extract_field`` resolves the segment through ``segments()``, which skips a
    # fieldless bare segment — so use the same matcher (a bare ``PID`` is not occurrence 1 when a
    # populated ``PID`` follows). A zero-match segments() raises KeyError in python-hl7, mapped to None
    # at the Peek layer; returning None here yields the identical observable result.
    seg_index = scan_segment_index(msg, seg_id, occurrence)
    if seg_index is None:
        return None
    _ensure_split(msg, seg_index)
    fields = msg["segments"][seg_index]["fields"]

    if comp is None:
        if fld < len(fields):
            return _field_text(fields[fld]) or None
        return None

    comp_num = comp or 1
    sub_num = sub if sub is not None else 1

    # MSH-1 / MSH-2 (and the BHS/FHS analogues) are constructed as single-element leaf fields and
    # never split — python-hl7 returns their value **raw** (un-unescaped) for a comp=1/sub=1 read, and
    # raises ``IndexError`` for any deeper index (the path runs past the leaf). Handle before the split
    # logic so MSH-2's ``^~\&`` is not mistaken for component structure.
    if seg_id in ("MSH", "BHS", "FHS") and fld in (1, 2):
        if fld < len(fields):
            if comp_num == 1 and sub_num == 1:
                return _field_text(fields[fld]) or None
            raise IndexError(
                f"Field reaches leaf node before completing path: {seg_id}.{fld}.{comp_num}"
            )

    # Field absent: python-hl7 returns "" only when the whole remaining path is position 1.
    if fld >= len(fields):
        if repetition == 1 and comp_num == 1 and sub_num == 1:
            return None  # "" -> None
        raise IndexError(f"Field not present: {seg_id}.{fld}")

    seps = msg["seps"]
    # First componentized touch materializes and caches the field's rep→comp→sub breakdown (ADR data
    # model). ``reps`` mirrors python-hl7's parse tree: a leaf at a level is a single-element list whose
    # one child is itself a single-element list (no separator was present at that depth).
    reps = _componentize(msg, seg_index, fld, seps)["reps"]

    if repetition > len(reps):
        # A repeat beyond the present ones: python-hl7 only ever returns "" (→ None) when the rest of
        # the path is position 1; otherwise it is an out-of-tree access. Reads never pass an
        # out-of-range repetition in practice, so guard defensively.
        if comp_num == 1 and sub_num == 1:
            return None
        raise IndexError(f"Repetition not present: {seg_id}.{fld}")
    rep = reps[repetition - 1]

    # Leaf at the repetition level (python-hl7's ``rep`` is a bare string): no component AND no
    # subcomponent separator was present, i.e. exactly one component carrying one subcomponent.
    if len(rep) == 1 and len(rep[0]) == 1:
        if comp_num == 1 and sub_num == 1:
            return unescape(rep[0][0], seps) or None
        raise IndexError(
            f"Field reaches leaf node before completing path: {seg_id}.{fld}.{comp_num}"
        )

    if comp_num > len(rep):
        if sub_num == 1:
            return None  # "" -> None (valid over-index)
        raise IndexError(f"Component not present: {seg_id}.{fld}.{comp_num}")
    comp_subs = rep[comp_num - 1]

    # Leaf at the component level (python-hl7's ``component`` is a bare string): one subcomponent.
    if len(comp_subs) == 1:
        if sub_num == 1:
            return unescape(comp_subs[0], seps) or None
        raise IndexError(
            f"Field reaches leaf node before completing path: {seg_id}.{fld}.{comp_num}.{sub_num}"
        )

    if sub_num <= len(comp_subs):
        return unescape(comp_subs[sub_num - 1], seps) or None
    return None  # "" -> None (valid over-index)


def extract_part(
    rep_text: str,
    comp: int,
    sub: int | None,
    seps: tuple[str, str, str, str, str],
) -> str | None:
    """Component/subcomponent within a single repetition's text — the ``Message`` string-level split.

    This is the semantics ``Message._extract`` uses: split ``rep_text`` only to the requested depth
    (never descend into first-children past it), unescape the leaf, and return None for an
    absent/empty part. It **diverges** from :func:`extract_field` on a subcomponent-only field: for
    ``rep_text='a&b'``, ``extract_part(comp=1, sub=None)`` returns ``'a&b'`` (whole component), whereas
    ``extract_field`` returns ``'a'`` (first subcomponent). Both are preserved by design.
    """
    _field, comp_sep, _rep_sep, sub_sep, _esc = seps
    comps = rep_text.split(comp_sep)
    if comp > len(comps):
        return None
    value = comps[comp - 1]
    if sub is None:
        return unescape(value, seps) or None
    subs = value.split(sub_sep)
    return (unescape(subs[sub - 1], seps) or None) if sub <= len(subs) else None


def segment_ids(msg: ParsedMessage) -> list[str]:
    """Ordered segment ids (``["MSH", "EVN", "PID", ...]``); an empty/blank segment is ``""``."""
    return [seg["id"] for seg in msg["segments"]]


def separators(msg: ParsedMessage) -> tuple[str, str, str, str, str]:
    """The message's ``(field, component, repetition, subcomponent, escape)`` separators."""
    return msg["seps"]


# ---------------------------------------------------------------------------
# Escape / unescape — byte-parity with hl7.util
# ---------------------------------------------------------------------------

# Upper bound on an HL7 rich-text repetition escape (e.g. ``\.in5\`` = indent 5). Real messages use
# tiny counts; without a cap, a ~15-byte ``\.in2000000000\`` expands to gigabytes synchronously on the
# event loop *before* the ACK — an unauthenticated memory-exhaustion DoS (DELTA-01). An over-limit or
# non-numeric count is treated as an unmappable sequence and dropped, matching python-hl7's own
# log-and-discard for sequences it cannot map. This is a deliberate divergence from python-hl7's
# UNBOUNDED expansion: the built-in is the default hot-path backend (ADR 0054), so it must be the one
# to bound the allocation (the upstream raw-size cap cannot — a tiny input expands past it).
MAX_ESCAPE_REPEAT = 512


def unescape(field: str, seps: tuple[str, str, str, str, str]) -> str:
    """Unescape an HL7 leaf value — byte-parity with ``hl7.util.unescape``.

    Converts ``\\F\\ \\S\\ \\R\\ \\T\\ \\E\\`` back to the message's own delimiters (read from
    ``seps``, never hardcoded), expands ``\\Xhh..\\`` hex runs, applies the rich-text/highlight map,
    and **drops** sequences it cannot map (matching python-hl7, which logs and discards them). A value
    with no escape character is returned unchanged. MSH-1/MSH-2 are never passed here (the caller
    returns them raw).
    """
    field_sep, comp_sep, rep_sep, sub_sep, esc = seps
    if not field or esc not in field:
        return field

    default_map = {
        "H": "_",
        "N": "_",
        "F": field_sep,
        "S": comp_sep,
        "R": rep_sep,
        "T": sub_sep,
        "E": esc,
        ".br": "\r",
        ".sp": "\r",
        ".fi": "",
        ".nf": "",
        ".in": "    ",
        ".ti": "    ",
        ".sk": " ",
        ".ce": "\r",
    }

    out: list[str] = []
    collecting: list[str] = []
    in_seq = False
    for c in field:
        if in_seq:
            if c == esc:
                in_seq = False
                value = "".join(collecting)
                collecting = []
                if not value:
                    continue
                if value in default_map:
                    out.append(default_map[value])
                elif value.startswith(".") and value[:3] in default_map:
                    try:
                        count = int(value[3:])
                    except ValueError:
                        # Non-numeric repeat count (e.g. ``\.inX\``): unmappable — drop it, matching
                        # the hex branch below and python-hl7's log-and-discard. (DELTA-02: an
                        # uncaught ValueError here previously escaped the pre-ACK summarize() and
                        # dropped a parseable message with no disposition, breaking count-and-log.)
                        continue
                    if not 0 <= count <= MAX_ESCAPE_REPEAT:
                        # Reject absurd/negative counts BEFORE the multiply (DELTA-01 DoS clamp).
                        continue
                    out.append(default_map[value[:3]] * count)
                elif value[0] in ("C", "M"):
                    # Inline character-set switches: python-hl7 logs and emits nothing.
                    continue
                elif value[0] == "X":
                    hexval = value[1:]
                    try:
                        for off in range(0, len(hexval), 2):
                            out.append(chr(int(hexval[off : off + 2], 16)))
                    except ValueError:
                        # python-hl7 logs and drops a malformed hex run.
                        continue
                # Any other sequence is unmappable: python-hl7 logs and drops it.
            else:
                collecting.append(c)
        elif c == esc:
            in_seq = True
        else:
            out.append(c)
    return "".join(out)


def escape_leaf(value: str, seps: tuple[str, str, str, str, str]) -> str:
    """Escape ONLY the structural delimiters (and the escape char) so ``value`` carries them as data.

    Mirrors ``Message._escape_leaf`` (NOT python-hl7's ``escape``, which hex-encodes non-ASCII and
    corrupts CJK/accented names): the escape char first (so we don't double-escape), then field /
    component / repetition / subcomponent → ``\\E\\ \\F\\ \\S\\ \\R\\ \\T\\``. Every other character,
    including code points above U+00FF, passes through and round-trips via :func:`unescape`.
    """
    field_sep, comp_sep, rep_sep, sub_sep, esc = seps
    out = value.replace(esc, f"{esc}E{esc}")
    out = out.replace(field_sep, f"{esc}F{esc}")
    out = out.replace(comp_sep, f"{esc}S{esc}")
    out = out.replace(rep_sep, f"{esc}R{esc}")
    out = out.replace(sub_sep, f"{esc}T{esc}")
    return out


# ---------------------------------------------------------------------------
# Writes
# ---------------------------------------------------------------------------


def set_field(
    msg: ParsedMessage, seg_id: str, fld: int, raw_value: str, occurrence: int = 1
) -> None:
    """Assign the whole raw field text at ``seg_id``-``fld`` for the ``occurrence``-th segment.

    The field list is extended with empty fields up to ``fld`` if needed (matching python-hl7's
    auto-extend on assignment). ``raw_value`` is the caller's already-built structural text
    (components/repetitions and any needed escaping done by the ``Message`` write path) and is stored
    verbatim as a bare ``str`` (re-componentized lazily on a later read). Marks the message dirty so
    the next :func:`encode` rebuilds the raw. Raises ``KeyError`` if the segment occurrence is absent.

    For ``occurrence == 1`` this routes through python-hl7's whole-field assignment
    (``msg["SEG.Fn"] = …`` → the raising ``segments()`` scan): a blank segment anywhere makes it raise
    ``IndexError``, a fieldless bare segment is skipped (so a bare ``PID`` before a populated one edits
    the populated), and a zero-match raises ``KeyError`` — all for byte-parity. A later occurrence uses
    the tolerant ``_segment_obj`` path (counts the bare segment, no blank-raise). (The ``Message`` write
    guard's tolerant presence check runs first, so a wholly-absent target is already a ``KeyError``.)
    """
    if occurrence == 1:
        raise_if_blank_segment_scan(msg)
        seg_index = scan_segment_index(msg, seg_id, occurrence)
    else:
        seg_index = _segment_index(msg, seg_id, occurrence)
    if seg_index is None:
        raise KeyError(f"cannot set absent segment {seg_id!r} occurrence {occurrence}")
    _ensure_split(msg, seg_index)
    fields = msg["segments"][seg_index]["fields"]
    while len(fields) <= fld:
        fields.append("")
    fields[fld] = raw_value
    msg["raw"] = None  # dirty: encode() must rebuild


def add_segment_line(
    msg: ParsedMessage, seg_id: str, fields: list[str], index: int | None = None
) -> None:
    """Insert a new segment built from ``fields`` (already field-split) at a 1-based ``index``.

    ``index`` is the position among segments (``1`` = just after MSH); ``None`` appends at the end.
    ``fields`` is the full list including the segment id at position 0 (so ``fields[0] == seg_id``).
    The segment is stored fully split (bare strings) so it never needs a lazy pass. Marks dirty.
    Raises ``ValueError`` on an out-of-range ``index``.
    """
    new_seg: Segment = {"id": seg_id, "fields": list(fields)}
    segments = msg["segments"]
    if index is None:
        segments.append(new_seg)
    else:
        if index < 1 or index > len(segments):
            raise ValueError(
                f"index {index} out of range (1..{len(segments)}); index 1 is after MSH"
            )
        segments.insert(index, new_seg)
        # Lazy keys are positional; an insert shifts every key at/after the insert point.
        if msg["_lazy"]:
            msg["_lazy"] = {(k + 1 if k >= index else k): v for k, v in msg["_lazy"].items()}
    msg["raw"] = None


def delete_segment_at(msg: ParsedMessage, index: int) -> None:
    """Delete the segment at list ``index`` (0-based), fixing up lazy keys. Marks dirty."""
    del msg["segments"][index]
    if msg["_lazy"]:
        msg["_lazy"] = {
            (k - 1 if k > index else k): v for k, v in msg["_lazy"].items() if k != index
        }
    msg["raw"] = None


# ---------------------------------------------------------------------------
# Encode
# ---------------------------------------------------------------------------


def _encode_segment(
    msg: ParsedMessage, seg_index: int, seps: tuple[str, str, str, str, str]
) -> str:
    """Rebuild one segment's ``\\r``-line raw text from its (possibly lazy) state.

    A still-lazy segment returns its cached raw line verbatim (no re-join needed — it was never
    touched). MSH/BHS/FHS rejoin with the hidden separator offset: ``id + MSH1 + MSH2 + MSH1 +
    field_sep.join(rest)``, mirroring ``hl7.Segment.__str__``. A field entry that componentized is
    re-joined from its raw ``text`` (writes update that text, so it is authoritative).
    """
    lazy_raw = msg["_lazy"].get(seg_index)
    if lazy_raw is not None:
        return lazy_raw

    seg = msg["segments"][seg_index]
    fields = seg["fields"]
    if not fields:
        return seg["id"]  # empty/blank segment

    field_sep = seps[0]
    texts = [_field_text(f) if not isinstance(f, str) else f for f in fields]
    if seg["id"] in ("MSH", "BHS", "FHS") and len(texts) >= 3:
        # texts: [id, MSH-1(field sep), MSH-2(enc chars), MSH-3, ...]
        return texts[0] + texts[1] + texts[2] + texts[1] + field_sep.join(texts[3:])
    return field_sep.join(texts)


def encode(msg: ParsedMessage) -> str:
    """Serialize back to a ``\\r``-delimited HL7 string (with the trailing ``\\r``).

    Returns the cached ``raw`` when the message is clean; otherwise rebuilds every segment from state
    and re-caches. Matches ``str(hl7.Message)``: segments joined on ``\\r`` plus a single trailing
    ``\\r``.
    """
    cached = msg["raw"]
    if cached is not None:
        return cached
    seps = msg["seps"]
    lines = [_encode_segment(msg, i, seps) for i in range(len(msg["segments"]))]
    rebuilt = "\r".join(lines) + "\r"
    msg["raw"] = rebuilt
    return rebuilt
