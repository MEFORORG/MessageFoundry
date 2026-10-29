# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Leak-check bridge (ADR 0030 §5) — the **non-parity seam** to the publish-guard's token authority.

A de-identified dataset is only safe to commit/share once it is **proven** free of known
customer/partner/site tokens — and that token set must be the SINGLE source of truth, not a third
copy that drifts (the very drift that already bit ``tests/test_load_config.py``). So the engine-side
leak-check delegates to ``scripts/security/scan_forbidden.py`` — the owner-managed guard — via
its importable :func:`scan_text`. The standalone ``tee/anon/leak.py`` vendors the same token data
(held identical by the parity test), since the tee cannot reach ``scripts/``.

The token denylist alone is a **backstop that only catches known *strings***: a real MRN in a field
the rule map never mapped is not a denylisted token, so it would sail through clean. Two structural
controls close that (BACKLOG #331), scoped to the fields ``anonymize`` did **not** rewrite so an
already-pseudonymized field is never re-flagged:

* an **unmapped-field coverage report** — every present-but-unmapped field is enumerated in the
  :class:`LeakReport` (address only, never its value), so the check's reach is legible and a field
  nobody thought to map is **recorded** (carried into the :class:`LeakError` on a refusal, and exposed
  via ``on_report``) rather than passing unrecorded; and
* **high-precision structural PHI-shape detectors** over those unmapped values (dashed SSN,
  punctuated NANP phone, CX ``MR``/``MRN``-typed identifier, and a line whose segment id is
  malformed), plus a dashed SSN or punctuated phone that the message's own field separator cut
  across fields, when at least one of them is unmapped (BACKLOG #3465) — narrow by design to
  avoid the mass false-positives a broad digit-run search would produce on HL7 bodies (ADR 0030
  §5). A name, an undashed number or a date in an unmapped field
  is NOT detected; the coverage report is the only record of it (BACKLOG #1710). The dashed SSN
  and punctuated phone detectors also scan what a retarget of a default field left past its
  first component (:func:`retarget_residue_hits`, BACKLOG #3493).

The token-floor signal (``token_floor_failure``) is recorded in every report
(``token_floor_reason``/``token_tables_live``) and folded into the fail-closed decision when
``require_live_denylist`` is set (default off), so a token-less load is legible to any caller that
inspects the report or opts into refusing on it.

Loaded lazily from the source checkout; an installed wheel without ``scripts/`` raises a clear error
(the anonymizer is a dev/migration tool, always run from a checkout).
"""

from __future__ import annotations

import importlib.util
import re
from bisect import bisect_left, bisect_right
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from types import ModuleType

from .rules import HEADER_SEGMENTS, AnonError, FieldRule, SurrogateKind, retargeted_defaults
from .surrogates import Seps, message_has_site_code, read_message_seps


class LeakCheckUnavailable(RuntimeError):
    """The publish-guard scanner could not be located (not run from a source checkout)."""


@lru_cache(maxsize=1)
def _scanner() -> ModuleType:
    # ONE path, built and never searched for (BACKLOG #2344). parents[2] is the folder that holds
    # this package: the repository root in a checkout, the install's package folder from a wheel.
    # Why that folder is the limit is stated once, in docs/DANGEROUS-FUNCTIONALITY.md, in the
    # paragraph that starts "`anon/leak.py` loads one file by path".
    candidate = Path(__file__).resolve().parents[2] / "scripts" / "security" / "scan_forbidden.py"
    if candidate.is_file():
        spec = importlib.util.spec_from_file_location("mefor_anon_scan_forbidden", candidate)
        if spec is not None and spec.loader is not None:
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
    raise LeakCheckUnavailable(
        f"could not locate the publish guard at {candidate} (the only path tried) — the anonymizer "
        "leak-check requires the source checkout, with this package imported from it (it is a "
        "dev/migration tool, not an installed-wheel runtime)"
    )


# --- structural PHI-shape detection over UNMAPPED fields (BACKLOG #331) ----------------------------
# EVERYTHING from here to the end of this block is held BYTE-IDENTICAL with tee/anon/leak.py (the
# structural walk depends only on read_message_seps, which the parity test pins byte-for-byte). The
# detectors are deliberately high-precision — a broad digit-run search mass-false-positives on HL7
# bodies dense with dates/order-numbers/set-ids (ADR 0030 §5), so the coverage report, not an
# aggressive heuristic, is the catch-all for shapes these cannot safely flag.

#: A dashed US SSN ``NNN-NN-NNNN`` not embedded in a longer digit run.
_SSN_DASHED: re.Pattern[str] = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
#: A punctuated NANP phone number: dashed ``NNN-NNN-NNNN`` or parenthesised ``(NNN) NNN-NNNN``. Only
#: PUNCTUATED forms are matched — a bare 10-digit run is indistinguishable from an order/account id.
_PHONE_DASHED: re.Pattern[str] = re.compile(r"(?<!\d)\d{3}-\d{3}-\d{4}(?!\d)")
_PHONE_PAREN: re.Pattern[str] = re.compile(r"\(\d{3}\)\s?\d{3}-\d{4}")
_SSN_REASON = "unmapped SSN-shaped value"
_PHONE_REASON = "unmapped phone-shaped value"
#: The punctuated shapes, each with its reason. A field separator that is one of their characters,
#: such as ``-``, cuts a value into several fields, none of which holds the shape whole, so each
#: line is also read as written for them (BACKLOG #3465).
_SPLITTABLE_SHAPES: tuple[tuple[re.Pattern[str], str], ...] = (
    (_SSN_DASHED, _SSN_REASON),
    (_PHONE_DASHED, _PHONE_REASON),
    (_PHONE_PAREN, _PHONE_REASON),
)


def _can_cut_a_shape(field_sep: str) -> bool:
    """True if ``field_sep`` is a character some :data:`_SPLITTABLE_SHAPES` match can hold: a
    digit, whitespace, ``-``, ``(`` or ``)``. Under any other, ``|`` among them, no line can hold
    a cut shape, so the walk skips the line scan."""
    return field_sep.isdigit() or field_sep.isspace() or field_sep in "-()"


#: HL7 CX id-type codes that mark a component as a medical-record number.
_MRN_TYPES: frozenset[str] = frozenset({"MR", "MRN"})
#: A well-formed HL7 segment id: a capital letter, then two capitals or digits (``PID``, ``ZPD``).
_SEGMENT_ID: re.Pattern[str] = re.compile(r"[A-Z][A-Z0-9]{2}")
#: The stand-in segment id for a line whose first field is NOT a segment id. That first field is
#: untrusted text (a wrapped name, a stray note line), so it must never become part of an address
#: that is raised, logged or printed. No rule can address such a line, so it is always unmapped.
MALFORMED_SEGMENT = "(malformed segment)"
#: The address a malformed line's first field always gets. :func:`structural_phi_hits` refuses on it.
_MALFORMED_LINE = f"{MALFORMED_SEGMENT}-0"
#: The hit a malformed line raises. Named so :func:`refusal_advice` can tell it from a PHI shape.
#: It names two of the kinds of line the walk refuses, in the words ``normalized_message`` uses,
#: so an operator reading it knows a short header line is one cause. It does not name a bare id
#: that is well formed but not defined, or an ``MSH`` line ahead of the header.
MALFORMED_LINE_HIT = (
    "line no rule can reach (a malformed segment id, or a header line with no separator after "
    "its encoding characters)"
)
#: The advice that goes with :data:`MALFORMED_LINE_HIT`.
MALFORMED_LINE_ADVICE = (
    "Repair the line no rule can reach: give it a well-formed segment id, or give a header line "
    "the separator after its encoding characters."
)
#: The stand-in segment id for a well-formed id that the message's HL7 version does not define and
#: that is not a Z-segment. A segment id is untrusted text too -- a wrapped ``KIM|F`` looks like a
#: segment -- so only a defined id, a Z-segment or an id a rule names is ever printed in an address.
UNKNOWN_SEGMENT = "(unknown segment)"
#: What follows the segment id in the address of a bare line that passed: a line with no field
#: separator whose whole text is an id the message's HL7 version defines or a rule names. That is
#: a legal empty segment, but a wrapped line of free text that is exactly such an id looks the
#: same, so the line gets a coverage record. The address holds no line position, so a long run
#: still keeps one entry per segment id (BACKLOG #3001).
BARE_LINE = " (line with no fields)"

#: The segment ids each HL7 v2 version defines, as (version, ids added, ids removed) from the version
#: before. Derived from hl7apy's tables and checked against them by ``tests/test_anon_core.py``; held
#: here as data because the tee cannot import hl7apy.
_SEGMENT_TABLE_CHANGES: tuple[tuple[str, str, str], ...] = (
    (
        "2.1",
        (
            "ACC ADD BHS BLG BTS DG1 DSC DSP ERR EVN FHS FT1 FTS GT1 IN1 MRG MSA MSH NCK NK1 "
            "NPU NSC NST NTE OBR OBX ORC ORO PD1 PID PR1 PV1 QRD QRF RX1 UB1 URD URS"
        ),
        "",
    ),
    (
        "2.2",
        (
            "AL1 IN2 IN3 MFA MFE MFI ODS ODT OM1 OM2 OM3 OM4 OM5 OM6 PRA PV2 RQ1 RQD RXA RXC "
            "RXD RXE RXG RXO RXR STF UB2"
        ),
        "ORO PD1 RX1",
    ),
    (
        "2.3",
        (
            "AIG AIL AIP AIS APR ARQ AUT CDM CM0 CM1 CM2 CSP CSR CSS CTD CTI DB1 DRG EQL ERQ "
            "FAC GOL LCC LCH LDP LOC LRL PCR PD1 PDC PEO PES PRB PRC PRD PSH PTH QAK RDF RDT "
            "RF1 RGS ROL SCH SPR TXA VAR VTQ"
        ),
        "",
    ),
    (
        "2.3.1",
        "",
        "",
    ),
    (
        "2.4",
        (
            "ABS AFF BLC CNS ECD ECR EDU EQP EQU GP1 GP2 IAM INV ISD LAN NDS OM7 ORG PDA QID "
            "QPD QRI RCP RMI SAC SID TCC TCD"
        ),
        "",
    ),
    (
        "2.5",
        "BPO BPX BTX CER CON IIM IPC OVR SFT SPM TQ1 TQ2",
        "",
    ),
    (
        "2.5.1",
        "",
        "",
    ),
    (
        "2.6",
        (
            "ADJ ARV DMI ILT IPR ITM IVC IVT PCE PKG PMT PSG PSL PSS PYE REL RFI SCD SCP SDD "
            "SLT STZ UAC VND"
        ),
        "EQL ERQ SPR VTQ",
    ),
    (
        "2.7",
        "IAR PAC PRT SHP",
        "",
    ),
    (
        "2.8",
        "BUI CDO DON RXV SGH SGT",
        "",
    ),
    (
        "2.8.1",
        "",
        "",
    ),
    (
        "2.8.2",
        "DPS MCP OMC PM1",
        "",
    ),
)


#: The longest run of digits :func:`_version_key` turns into a number. No HL7 version comes near
#: it. The interpreter refuses to convert a run past its own limit (4300 digits unless that
#: setting is changed or turned off) with a plain ``ValueError``, so the length is capped here,
#: well under that limit, and the refusal does not depend on the setting (BACKLOG #3004).
_VERSION_PART_MAX_DIGITS = 32


def _version_key(version: str) -> tuple[int, ...] | None:
    parts = version.strip().split(".")
    # ASCII digits only: a superscript two passes str.isdigit() and then int() raises on it,
    # and MSH-12 is untrusted text that must not reach an error message (BACKLOG #2246).
    if not all(part.isascii() and part.isdigit() for part in parts):
        return None
    if any(len(part) > _VERSION_PART_MAX_DIGITS for part in parts):
        raise AnonError(
            "message has an HL7 version in MSH-12 with a run of digits too long to read — "
            "refusing to emit; repair the header, then retry"
        )
    return tuple(int(part) for part in parts)


def _segment_tables() -> tuple[tuple[tuple[int, ...], frozenset[str]], ...]:
    tables: list[tuple[tuple[int, ...], frozenset[str]]] = []
    ids: set[str] = set()
    for version, added, removed in _SEGMENT_TABLE_CHANGES:
        ids = (ids | set(added.split())) - set(removed.split())
        tables.append((_version_key(version) or (), frozenset(ids)))
    return tuple(tables)


_SEGMENT_TABLES = _segment_tables()
_ANY_VERSION_SEGMENTS: frozenset[str] = frozenset().union(*(ids for _, ids in _SEGMENT_TABLES))


def known_segments(version: str) -> frozenset[str]:
    """The segment ids HL7 ``version`` (MSH-12) defines: the newest table at or below it. An empty or
    unparseable version, or one older than every table, gets the ids that ANY version defines, which
    names more than the message's own version would. A version with a run of more than
    :data:`_VERSION_PART_MAX_DIGITS` digits raises a body-free :class:`AnonError`."""
    key = _version_key(version)
    chosen: frozenset[str] | None = None
    if key is not None:
        for table_key, ids in _SEGMENT_TABLES:
            if table_key <= key:
                chosen = ids
    return chosen if chosen is not None else _ANY_VERSION_SEGMENTS


#: The fewest split fields a header line (``HEADER_SEGMENTS``) can have: the id, the encoding
#: characters, and one field after them. The separator that ends the encoding characters is what
#: the engine's parser looks for. Without it the parser cuts the encoding characters short and
#: re-encodes the line with its own text repeated (BACKLOG #2998).
_HEADER_MIN_FIELDS = 3


def _line_is_malformed(fields: list[str], defined: frozenset[str] | set[str]) -> bool:
    """True if no rule can reach this line. Either its first field is not a well-formed segment
    id, or the line has no field separator and its text is not an id in ``defined``.

    A segment with no fields is legal HL7, so a bare ``PV2`` is an empty segment and passes;
    :func:`unmapped_field_values` gives it a coverage record. A bare ``LEE`` or ``ZOE`` is three
    letters of untrusted text that no rule can address, so it is malformed. ``defined`` is the ids
    the message's HL7 version defines plus the ids a rule names, so a bare ``ZPD`` is an empty
    segment only when a rule names ``ZPD``. A Z-prefix alone does not count (BACKLOG #2247).

    A header line (``MSH``, ``FHS``, ``BHS``) is malformed with fewer than
    :data:`_HEADER_MIN_FIELDS` split fields. A bare one carries no separators, and the engine's
    parser refuses it where the tee would emit it. One with no separator after its encoding
    characters (``BHS|TEXT``) is re-encoded out of shape by the engine, with ``TEXT`` written
    twice, where the tee would emit it as it came (BACKLOG #2998)."""
    seg_id = fields[0]
    if not _SEGMENT_ID.fullmatch(seg_id):
        return True
    if seg_id in HEADER_SEGMENTS:
        return len(fields) < _HEADER_MIN_FIELDS
    return len(fields) == 1 and seg_id not in defined


def _header_version(header: list[str], seps: Seps) -> str:
    """The version id in MSH-12 of a header line already split into fields."""
    return header[11].split(seps.component)[0] if len(header) > 11 else ""


def _split_at_header(text: str) -> tuple[Seps, str, list[str], int] | None:
    """The separators of ``text``, its lines, and the index of its header: the first line
    ``read_message_seps`` accepts. ``None`` when the message has no parseable MSH."""
    parsed = read_message_seps(text)
    if parsed is None:
        return None
    seps, field_sep = parsed
    lines = text.replace("\r\n", "\r").replace("\n", "\r").split("\r")
    # read_message_seps accepted one of these lines, so the search cannot come back empty.
    header_at = next(n for n, seg in enumerate(lines) if read_message_seps(seg) is not None)
    return seps, field_sep, lines, header_at


def message_version(text: str) -> str | None:
    """The HL7 version in MSH-12 of the header of ``text``: the first line ``read_message_seps``
    accepts, the same line :func:`unmapped_field_values` takes as the header. ``None`` when the
    message has no parseable MSH. MLLP framing bytes are dropped first, as ``normalized_message``
    drops them, so a captured message reads the same as its normalized form.

    ``anonymize_checked`` reads this from its INPUT and hands it to :func:`leak_report`, so the
    leak-check judges a bare line by the version the message came with (BACKLOG #3004)."""
    found = _split_at_header(text.replace("\x0b", "").replace("\x1c", ""))
    if found is None:
        return None
    seps, field_sep, lines, header_at = found
    return _header_version(lines[header_at].split(field_sep), seps)


def unmapped_field_values(
    text: str,
    mapped_paths: set[str],
    *,
    version: str | None = None,
    named_by: Iterable[str] | None = None,
) -> list[tuple[str, str]]:
    """Every ``(address, value)`` in ``text`` whose whole-field ``SEG-i`` address is **not** in
    ``mapped_paths`` and whose value is non-empty — the fields the rule map never touched. One
    kind of record has an empty value: the one a bare line gets, described below.

    ``version`` is the HL7 version whose segment ids count as defined. It decides which bare line
    passes, and which segment ids are printed in an address rather than as
    :data:`UNKNOWN_SEGMENT`, so pass only the version the message really came with. Left out, it
    is read from the header of ``text``. A caller that checks OUTPUT passes the version of the
    INPUT (:func:`message_version`): a rule on MSH-12 writes a surrogate there, and a surrogate
    version can leave out an id the real version defines, so a line that passed on the way in
    would be refused on the way out (BACKLOG #3004).

    The MSH control header is skipped whole: it carries routing/site data the field-anchored
    site-code pass already covers, not patient PHI. The header is the ONE line
    ``read_message_seps`` takes the separators from, and no other. An ``MSH`` line ahead of it is
    not the header: it is walked, and refused whatever it holds, where one after the header is
    refused only when it is bare or short. Every line,
    whichever side of the header it sits on, is judged against the header's own MSH-12 version
    (BACKLOG #3001). A later MSH line is checked. It, and every ``BHS`` and ``FHS`` line, is
    numbered the header way: field N sits at split index N-1, because field 1 is the separator
    itself. Both adapters apply a rule to that same field (BACKLOG #2265, #2998).
    ``mapped_paths`` is occurrence-agnostic (a rule applies to every occurrence of its segment),
    so the address is the bare ``SEG-i``. Returns ``[]`` when the message has no parseable MSH
    (there is no field separator to split on).

    A line whose first field is not a well-formed segment id, or that has no field separator and
    is not an id the message's HL7 version defines or a rule names (a wrapped ``LEE`` looks like a
    segment id; a bare ``PV2`` is a legal empty segment), is reported under :data:`MALFORMED_SEGMENT`,
    first field included as index 0, so its text reaches the detectors but never an address.
    :func:`structural_phi_hits` refuses such a line outright. A line holding only whitespace or
    control characters (NUL padding, a trailing SUB) carries nothing and is skipped.

    A bare line that passes gets one record: its segment id followed by :data:`BARE_LINE`, with
    an empty value. No rule can rewrite it, so the record is there whatever ``mapped_paths``
    holds, and :func:`leak_report` decides whether it counts as decided (BACKLOG #3001).

    A well-formed id that the header's MSH-12 version does not define, is not a Z-segment and no
    rule names is addressed as :data:`UNKNOWN_SEGMENT`: its fields are still checked, but the id
    itself, which may be a wrapped name, is never printed.

    ``named_by`` is the rule paths whose segment ids count as named, ``mapped_paths`` when left
    out. :func:`retarget_residue_hits` walks with fewer paths mapped than the rules name, and
    passes every rule's path here so a segment only a retarget names keeps its address.
    """
    return _walk(text, mapped_paths, version, split=False, named_by=named_by)[0]


def _walk(
    text: str,
    mapped_paths: set[str],
    version: str | None,
    *,
    split: bool,
    named_by: Iterable[str] | None = None,
) -> tuple[list[tuple[str, str]], list[str]]:
    """The walk behind :func:`unmapped_field_values`, which returns the first half. With ``split``,
    the second half is the hits :func:`_split_shape_hits` finds on each line the walk reads field
    by field; without it, the second half is empty and no line is scanned for them. ``named_by``
    is as :func:`unmapped_field_values` says."""
    found = _split_at_header(text)
    if found is None:
        return [], []
    seps, field_sep, lines, header_at = found
    out: list[tuple[str, str]] = []
    split_hits: list[str] = []
    split = split and _can_cut_a_shape(field_sep)
    if version is None:
        version = _header_version(lines[header_at].split(field_sep), seps)
    naming = mapped_paths if named_by is None else named_by
    nameable = known_segments(version) | {path.split("-", 1)[0] for path in naming}
    for n, seg in enumerate(lines):
        if all(c.isspace() or not c.isprintable() for c in seg):
            continue
        fields = seg.split(field_sep)
        seg_id = fields[0]
        is_msh = seg_id.upper() == "MSH"
        # A header whose separator is a letter of its own id does not split to an MSH id. It is
        # not skipped, and the check below refuses it, as it did before the header was found
        # by line.
        if n == header_at and is_msh:
            continue
        # One address per split index; None for a field the check does not judge.
        addresses: list[str | None]
        # An MSH line ahead of the header is refused whatever it holds. The tee adapter takes
        # the FIRST line whose id reads MSH as its header, so with one here an MSH rule would
        # miss the real header, which this walk never checks.
        if _line_is_malformed(fields, nameable) or (n < header_at and is_msh):
            # Index 0 is _MALFORMED_LINE, recorded even when empty.
            addresses = [f"{MALFORMED_SEGMENT}-{i}" for i in range(len(fields))]
        elif len(fields) == 1:
            # A bare id that passed is in ``nameable``, so it is safe to print. The value is
            # empty: the id is all the line holds, and an empty value trips no detector.
            out.append((f"{seg_id}{BARE_LINE}", ""))
            continue
        else:
            named = seg_id if seg_id in nameable or seg_id.startswith("Z") else UNKNOWN_SEGMENT
            shift = 1 if seg_id in HEADER_SEGMENTS else 0  # field 1 is the separator itself
            # The segment id is no field, and a field a rule rewrites is not judged.
            addresses = [
                None,
                *(
                    None if f"{seg_id}-{i + shift}" in mapped_paths else f"{named}-{i + shift}"
                    for i in range(1, len(fields))
                ),
            ]
        out.extend(
            (a, v)
            for a, v in zip(addresses, fields, strict=True)
            if a is not None and (v or a == _MALFORMED_LINE)
        )
        if split:
            split_hits.extend(_split_shape_hits(seg, field_sep, addresses))
    return out, split_hits


def _split_shape_hits(line: str, field_sep: str, addresses: Sequence[str | None]) -> list[str]:
    """Hits for a punctuated shape (:data:`_SPLITTABLE_SHAPES`) that the field separator cuts
    across fields of ``line``: a match on the line as written that holds the separator, so no one
    field held it whole (BACKLOG #3465). Under ``|`` no such match exists.

    ``addresses`` names each split index of the line, ``None`` for a field the check does not
    judge. A match is a hit when at least one field it reaches has an address, and the hit names
    the first and last of those. So a match that starts in a field a rule rewrote is a hit when it
    runs on into a field no rule rewrites: the shape reached the output whole. What still passes
    is listed once, in docs/PHI.md section 9."""
    hits: list[str] = []
    cuts = [i for i, c in enumerate(line) if c == field_sep]
    for pattern, reason in _SPLITTABLE_SHAPES:
        for match in pattern.finditer(line):
            if field_sep not in match.group():
                continue
            # The fields that hold a character of the match: the separators at or before its first
            # character, and those before its last. A separator at its first character belongs
            # to no field, so counting it starts at the next field. Positions are found once per
            # line, so a long line costs a search per match, not a rescan.
            first = bisect_right(cuts, match.start())
            last = bisect_left(cuts, match.end() - 1)
            named = [a for a in addresses[first : last + 1] if a is not None]
            if named:
                span = named[0] if len(named) == 1 else f"{named[0]} to {named[-1]}"
                hits.append(f"{reason} across {span}, cut by the field separator")
    return hits


def _has_mrn_typed_identifier(value: str, seps: Seps) -> bool:
    """True if any repetition of ``value`` is a CX with a non-empty id (component 1) and a whole
    ``MR``/``MRN`` id-type component — an unmapped medical-record number by HL7 structure, far more
    precise than a bare digit-run heuristic."""
    for rep in value.split(seps.repetition):
        comps = rep.split(seps.component)
        if comps[0] and any(comp.upper() in _MRN_TYPES for comp in comps):
            return True
    return False


def _structural_reasons(value: str, seps: Seps) -> list[str]:
    """PHI-safe shape labels for one unmapped field value — the SHAPE only, never the value."""
    reasons: list[str] = []
    for pattern, reason in _SPLITTABLE_SHAPES:
        if reason not in reasons and pattern.search(value):
            reasons.append(reason)
    if _has_mrn_typed_identifier(value, seps):
        reasons.append("unmapped MRN-typed identifier")
    return reasons


def structural_phi_hits(
    text: str, mapped_paths: set[str], *, version: str | None = None
) -> list[str]:
    """Structural PHI-shape hits over the fields no rule matched — reasons name the shape + field
    ADDRESS only (e.g. ``"unmapped SSN-shaped value in ZPD-4"``), never the offending value, so the
    result is safe to raise/log. Empty when the message has no parseable MSH. ``version`` is
    handed to the walk behind :func:`unmapped_field_values`.

    A line no rule can reach (a malformed segment id, or a short header line; see
    :func:`_line_is_malformed`) is a hit by itself, whatever it holds: the anonymizer passed it
    through untouched, and a wrapped name or note is exactly what such a line tends to carry.

    A dashed SSN or punctuated phone that the message's own field separator cuts across fields
    is a hit too, named by the fields it spans (:func:`_split_shape_hits`, BACKLOG #3465)."""
    parsed = read_message_seps(text)
    if parsed is None:
        return []
    seps, _field_sep = parsed
    hits: list[str] = []
    walked, split_hits = _walk(text, mapped_paths, version, split=True)
    for address, value in walked:
        if address == _MALFORMED_LINE:
            hits.append(MALFORMED_LINE_HIT)
        hits.extend(f"{reason} in {address}" for reason in _structural_reasons(value, seps))
    return hits + split_hits


#: What a hit in the part of a field a retarget left reads as, after its shape label.
RETARGET_RESIDUE = "left by a retarget"


def retarget_residue_hits(
    text: str, rules: tuple[FieldRule, ...], *, version: str | None = None
) -> list[str]:
    """Structural PHI-shape hits in what a retarget of a default field left in ``text``
    (BACKLOG #3493). Reasons name the shape and the field address only, never a value.

    A rule that points a default field at a different kind (:func:`.rules.retargeted_defaults`)
    maps the field, so :func:`structural_phi_hits` never scans it. ``id``, ``mrn`` and ``ssn``
    rewrite component 1 only, and the rest of the captured value stays. So each repetition of
    such a field is scanned here with its component 1 left out, for the dashed SSN and the
    punctuated phone. The MRN-typed shape needs a component 1, so it never fires here, which is
    right: the id there is the surrogate. The other kinds add no hit: ``name``, ``address`` and
    ``provider`` write values from fixed pools, and ``tests/test_anon_overlay_retarget_warning.py``
    pins that no pool value has one of these shapes; ``phone`` and ``dob`` write one component;
    ``date`` writes component 1 and keeps after it only a known TS.2 precision code.

    The walk names a segment by every rule's path, so a segment only the retarget names keeps
    its address in a message whose HL7 version does not define it."""
    retargeted = {default.path for default, _ in retargeted_defaults(rules)}
    parsed = read_message_seps(text)
    if not retargeted or parsed is None:
        return []
    seps = parsed[0]
    rewritten = {r.path for r in rules if r.kind != SurrogateKind.KEEP}
    hits: list[str] = []
    walk = unmapped_field_values(text, rewritten - retargeted, version=version, named_by=rewritten)
    for address, value in walk:
        if address not in retargeted:
            continue
        rest = seps.repetition.join(
            seps.component.join(["", *rep.split(seps.component)[1:]])
            for rep in value.split(seps.repetition)
        )
        hits.extend(
            f"{reason.removeprefix('unmapped ')} {RETARGET_RESIDUE} in {address}"
            for reason in _structural_reasons(rest, seps)
        )
    return hits


def has_unreachable_line(text: str, mapped_paths: Iterable[str] = ()) -> bool:
    """True if ``text`` holds a line no rule can reach, by the same walk the leak-check uses.
    ``normalized_message`` refuses on it, so plain ``anonymize`` and ``anonymize_checked`` agree
    (BACKLOG #2246). False when the message has no parseable MSH; the adapters refuse that.

    ``mapped_paths`` is the paths of the rules that rewrite a field, the same set
    :func:`structural_phi_hits` is given. A segment id one of them names may stand bare, so this
    and the leak-check accept and refuse the same lines for the same rules."""
    paths = set(mapped_paths)
    return any(address == _MALFORMED_LINE for address, _ in unmapped_field_values(text, paths))


#: Fields ``require_full_coverage`` needs no rule for, but only while the value has the expected
#: shape (:func:`_decided_by_shape`): every set id (field 1 typed SI in HL7 2.5.1, or in the newest
#: version for a segment 2.5.1 lacks; ``tests/test_anon_core.py`` checks it against hl7apy), PID-8
#: administrative sex and PV1-2 patient class. They are still scanned for PHI shapes.
_SET_ID_SEGMENTS = (
    "AFF AIG AIL AIP AIS AL1 ARV BPO BPX BTX BUI CDO CER CM0 CM1 CM2 CON DB1 DG1 "
    "DSP EDU FT1 GT1 IAM ILT IN1 IN3 IVT LAN MCP NK1 NTE OBR OBX ORG PAC PCE PID "
    "PKG PR1 PV1 PYE REL RGS RQD RXV SGH SGT SPM TQ1 TQ2 TXA UB1 UB2 VND"
)
_CODED: frozenset[str] = frozenset({"PID-8", "PV1-2"})
ALWAYS_DECIDED: frozenset[str] = frozenset(
    {f"{segment}-1" for segment in _SET_ID_SEGMENTS.split()} | _CODED
)
_SET_ID_VALUE: re.Pattern[str] = re.compile(r"[0-9]{1,4}")
_SHORT_CODE: re.Pattern[str] = re.compile(r"[A-Za-z0-9]{1,2}")


def _decided_by_shape(address: str, value: str, seps: Seps) -> bool:
    """True if ``address`` is on :data:`ALWAYS_DECIDED` AND ``value`` looks like what belongs there:
    a set id of one to four digits, or a sex/patient-class code of one or two characters and
    nothing else (no component or repetition). A name in ``NTE-1``, or ``M^`` followed by a name
    in ``PID-8``, is therefore still undecided; so is a CWE with its text components."""
    if address not in ALWAYS_DECIDED:
        return False
    if address in _CODED:
        return _SHORT_CODE.fullmatch(value) is not None
    return _SET_ID_VALUE.fullmatch(value) is not None


@dataclass(frozen=True)
class LeakReport:
    """The full result of a leak-check pass — the token hits that decide the fail-closed outcome plus
    the coverage context that makes the check's reach legible (all PHI-safe: addresses and reasons,
    never a field value).

    * ``hits`` — every leak reason (token/IP/site + structural); non-empty means refuse.
    * ``unmapped_fields`` — the addresses present but matched by no rule (the coverage report).
    * ``structural_hits`` — the subset of ``hits`` from the structural PHI-shape detectors.
    * ``token_tables_live`` — whether the denylist tables loaded from a real token source.
    * ``token_floor_reason`` — why the denylist is not trustworthy, or ``None`` if it is.
    * ``undecided_fields`` — the addresses present that no rule scrubs, no ``keep`` names and
      :data:`ALWAYS_DECIDED` does not excuse; ``require_full_coverage`` refuses on them. A bare
      line's address (:data:`BARE_LINE`) is here unless a rule or a ``keep`` names any field of
      its segment.
    * ``blanked_fields`` — the addresses where the ``DATE`` kind scrubbed a value it could
      not keep to empty. Only ``anonymize_checked`` fills it: this report is built from the
      output, where an emptied field looks like one that was never sent (BACKLOG #2330).
    """

    hits: list[str]
    unmapped_fields: tuple[str, ...]
    structural_hits: list[str]
    token_tables_live: bool
    token_floor_reason: str | None
    undecided_fields: tuple[str, ...] = ()
    blanked_fields: tuple[str, ...] = ()


def leak_report(
    text: str, *, rules: tuple[FieldRule, ...] | None = None, version: str | None = None
) -> LeakReport:
    """The full :class:`LeakReport` for ``text`` using the publish-guard's token authority.

    Token hits use the guard's substring + estate-token mode (ADR 0030 §5) plus a field-anchored
    site-code check. Structural detection engages **only when ``rules`` is supplied** — the address
    of every unmapped field is derived from ``{r.path for r in rules}`` and the high-precision
    detectors run over those fields, and over what a retarget of a default field left past its
    first component (:func:`retarget_residue_hits`). With ``rules is None`` (a direct/legacy
    call over a bare string) structural detection is skipped and the result is byte-for-byte the legacy token-only behaviour.

    ``version`` is the HL7 version a bare line is judged by. A caller that checks the OUTPUT of
    ``anonymize`` passes the version of the INPUT (:func:`message_version`), because a rule may
    have rewritten MSH-12. Left out, the version is read from ``text`` (BACKLOG #3004).
    """
    scanner = _scanner()
    token_hits = [str(h) for h in scanner.scan_text(text, include_estate=True)]
    # The rules scope this check too: a field the DATE kind filled is not a site code (#2330).
    if message_has_site_code(text, rules or ()):
        token_hits.append("site-code pattern")
    undecided: tuple[str, ...] = ()
    if rules is None:
        unmapped: tuple[str, ...] = ()
        structural: list[str] = []
    else:
        # A KEEP rule rewrote nothing, so its field stays in the detectors' scope; it only
        # counts as DECIDED for the coverage switch (BACKLOG #1710).
        # ``!=``, not ``is not``: StrEnum compares by value, so an engine or plain "keep" counts too.
        mapped_paths = {r.path for r in rules if r.kind != SurrogateKind.KEEP}
        walked = unmapped_field_values(text, mapped_paths, version=version)
        unmapped = tuple(sorted({addr for addr, _ in walked}))
        structural = structural_phi_hits(text, mapped_paths, version=version)
        structural += retarget_residue_hits(text, rules, version=version)
        decided = {r.path for r in rules}
        # A bare line has no field a rule could name, so a rule or a keep on ANY field of its
        # segment decides it (BACKLOG #3001).
        decided_bare = {f"{path.split('-', 1)[0]}{BARE_LINE}" for path in decided}
        parsed = read_message_seps(text)
        seps = parsed[0] if parsed is not None else Seps()
        undecided = tuple(
            sorted(
                {
                    address
                    for address, value in unmapped_field_values(text, decided, version=version)
                    if address not in decided_bare and not _decided_by_shape(address, value, seps)
                }
            )
        )
    token_tables_live = bool(scanner.TOKENS_PRESENT)
    token_floor_reason: str | None = scanner.token_floor_failure()
    return LeakReport(
        hits=token_hits + structural,
        unmapped_fields=unmapped,
        structural_hits=structural,
        token_tables_live=token_tables_live,
        token_floor_reason=token_floor_reason,
        undecided_fields=undecided,
    )


def leak_check(
    text: str, *, rules: tuple[FieldRule, ...] | None = None, version: str | None = None
) -> list[str]:
    """Forbidden-token + structural PHI hits in ``text`` (empty list = clean) — a thin wrapper over
    :func:`leak_report`. ``rules`` scopes the structural PHI-shape detectors to the fields no rule
    matched and to what a retarget left; omitting it (a bare-string call) runs the legacy
    token-only check. A caller that
    ran ``anonymize`` itself passes ``version=message_version(raw)``, as :func:`leak_report` says.
    """
    return leak_report(text, rules=rules, version=version).hits


def coverage_clause(report: LeakReport) -> str:
    """A PHI-safe suffix for a fail-closed message naming what the check reached — the count and
    ADDRESSES of the unmapped fields (never their values) and whether the denylist tables were live."""
    live = "yes" if denylist_is_live(report) else "no"
    fields = ", ".join(report.unmapped_fields) if report.unmapped_fields else "none"
    return (
        f" (checked {len(report.unmapped_fields)} unmapped field(s): {fields}; "
        f"denylist tables live: {live})"
    )


def denylist_is_live(report: LeakReport) -> bool:
    """True only if the token tables loaded AND passed the floor check. ``token_tables_live`` alone
    is true for a source that lost a whole section, which ``token_floor_reason`` then names, so
    printing "live" from the first field alone overstated the check (BACKLOG #2247)."""
    return report.token_tables_live and report.token_floor_reason is None


#: What to do about a hit in what a retarget left. A keep would leave the whole field instead.
RETARGET_ADVICE = "Point each retargeted field back at its default kind, or at drop or freetext."


def has_retarget_residue(report: LeakReport) -> bool:
    """True if ``report`` holds a hit from :func:`retarget_residue_hits`."""
    return any(RETARGET_RESIDUE in hit for hit in report.structural_hits)


def refusal_advice(
    report: LeakReport, *, denylist_refused: bool = False, coverage_refused: bool = False
) -> str:
    """What to do about a refusal: one sentence per KIND of cause that fired, and no others.
    Every refusal used to suggest repairing a malformed line, even when a token was the cause
    (BACKLOG #2247). PHI-safe: fixed text, chosen by the kind of hit and never by a value."""
    steps: list[str] = []
    token_hit = len(report.hits) > len(report.structural_hits)
    shape_hit = any(
        hit != MALFORMED_LINE_HIT and RETARGET_RESIDUE not in hit for hit in report.structural_hits
    )
    if token_hit or shape_hit:
        steps.append("Extend the rule map so the field that carries it is scrubbed.")
    if has_retarget_residue(report):
        steps.append(RETARGET_ADVICE)
    if coverage_refused:
        steps.append("Add a rule for each field named, or a keep for one you reviewed.")
        if any(address.endswith(BARE_LINE) for address in report.undecided_fields):
            steps.append(
                "For a line with no fields, add a rule or a keep for any field of that segment."
            )
    if MALFORMED_LINE_HIT in report.structural_hits:
        steps.append(MALFORMED_LINE_ADVICE)
    if denylist_refused:
        steps.append("Load the denylist token source.")
    return " ".join(steps)


#: What the structural detectors look for in an unmapped field, and what they let through. Stated once
#: here so the run summary cannot drift from the detectors above (docs/PHI.md section 9 is the long form).
UNMAPPED_SCOPE_NOTE = (
    "Beyond the partner-token and IP scan of the whole message, the leak-check looks in these "
    "fields only for a dashed SSN, a punctuated phone number and an MR/MRN-typed identifier. A "
    "name, an undashed number or a date in one of them passes, so review this list before you "
    "share the dataset."
)


class CoverageTally:
    """The unmapped-field coverage across many messages, kept as counts rather than as reports so a
    long run holds one entry per distinct address. PHI-safe: addresses and counts, never a value.
    Pass :meth:`add` as ``anonymize_checked``'s ``on_report``.

    ``anonymize_checked`` calls ``on_report`` only for a message that reached the leak-check. One
    it refuses first, with :class:`AnonError`, builds no report, so a caller that wants the
    summary to show it calls :meth:`refuse` when it catches that error (BACKLOG #3004)."""

    def __init__(self, *, full_coverage: bool = False) -> None:
        self.messages = 0
        self.refused = 0
        self.counts: Counter[str] = Counter()
        self.undecided: Counter[str] = Counter()
        self.blanked: Counter[str] = Counter()
        self.full_coverage = full_coverage
        self.denylist_live = True

    def add(self, report: LeakReport) -> None:
        self.messages += 1
        self.counts.update(report.unmapped_fields)
        self.undecided.update(report.undecided_fields)
        self.blanked.update(report.blanked_fields)
        self.denylist_live = self.denylist_live and denylist_is_live(report)

    def refuse(self) -> None:
        """Count one message ``anonymize`` refused with :class:`AnonError`, before any report."""
        self.refused += 1

    def summary(self) -> str:
        live = "yes" if self.messages and self.denylist_live else "no"
        fields = ", ".join(f"{a} x{n}" for a, n in sorted(self.counts.items())) or "none"
        text = (
            f"coverage: {self.messages} message(s) reached the leak-check; {len(self.counts)} "
            f"field address(es) had no rule: {fields}; denylist tables live: {live}. "
            + UNMAPPED_SCOPE_NOTE
        )
        if self.full_coverage:
            todo = ", ".join(f"{a} x{n}" for a, n in sorted(self.undecided.items())) or "none"
            text += f" Fields that need a rule or a keep for require_full_coverage: {todo}."
        if self.blanked:
            gone = ", ".join(f"{a} x{n}" for a, n in sorted(self.blanked.items()))
            text += (
                f" Date fields emptied because the value was not a timestamp it could keep: {gone}."
            )
        if any(address.endswith(BARE_LINE) for address in self.counts):
            # The entry reads like a field address and is not one, and the advice a LeakError
            # carries never reaches an operator whose caller prints its own text (BACKLOG #3004).
            text += (
                f" An entry that ends in '{BARE_LINE.strip()}' is a line holding only that "
                "segment id. It is not an overlay key. A rule or a keep on any field of that "
                "segment decides it."
            )
        if self.refused:
            text += (
                f" Not counted above: {self.refused} message(s) refused before the leak-check "
                "built a report. This line cannot say which cause applies. Among the causes, at "
                "least: no parseable MSH; a line no rule can reach, which a report would list "
                f"as {_MALFORMED_LINE}; an HL7 version in MSH-12 with a run of digits too long "
                "to read."
            )
        return text
