# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Leak-check bridge (ADR 0030 §5) — the **non-parity seam** to the publish-guard's token authority.

A de-identified dataset is only safe to commit/share once it is **proven** free of known
customer/partner/site tokens — and that token set must be the SINGLE source of truth, not a third
copy that drifts (the very drift that already bit ``tests/test_load_config.py``). So the toolkit-side
leak-check delegates to ``scripts/security/scan_forbidden.py`` — the owner-managed guard — via
its importable :func:`scan_text`. The standalone ``tee/anon/leak.py`` loads the same guard by
path and reads its name and estate tables at each scan, so it holds no copy of them.

The token denylist alone is a **backstop that only catches known *strings***: a real MRN in a field
the rule map never mapped is not a denylisted token, so it would sail through clean. Two structural
controls close that (BACKLOG #331), scoped to the fields ``anonymize`` did **not** rewrite so an
already-pseudonymized field is never re-flagged:

* an **unmapped-field coverage report** — every present-but-unmapped field is enumerated in the
  :class:`LeakReport` (address only, never its value), so the check's reach is legible and a field
  nobody thought to map is **recorded** (carried into the :class:`LeakError` on a refusal, and exposed
  via ``on_report``) rather than passing unrecorded; and
* **high-precision structural PHI-shape detectors** over those unmapped values (dashed SSN,
  punctuated NANP phone, an ``MR``/``MRN`` id type in a whole component, its first subcomponent
  or any subcomponent of CX.5, a routable IPv6 address, and a line whose segment id is
  malformed; the IPv6 detector alone also reads the MSH header's fields from MSH-3 on that no
  rule rewrites), plus a dashed SSN or punctuated phone that the message's own field separator cut
  across fields, when at least one of them is unmapped (BACKLOG #3465) — narrow by design to
  avoid the mass false-positives a broad digit-run search would produce on HL7 bodies (ADR 0030
  §5). A name, an undashed number or a date in an unmapped field
  is NOT detected; the coverage report is the only record of it (BACKLOG #1710). The dashed SSN
  and punctuated phone detectors also scan what a retarget of a default field left past its
  first component (:func:`retarget_residue_hits`, BACKLOG #3493), and the components an ``id``,
  ``mrn``, ``ssn`` or ``dln`` rule keeps as captured past its first (:func:`kept_component_hits`,
  BACKLOG #5533, #5534). The shape detectors that read
  one field, and the token scan, read a value decoded from its HL7 escape sequences as well as as
  written, so a shape or token written ``\\X2D\\`` for a dash is found too (BACKLOG #5532).
  docs/PHI.md section 9, *An escaped value is read decoded too*, lists at least the escaped
  forms each check still passes.

The token-floor signal (``token_floor_failure``) is recorded in every report
(``token_floor_reason``/``token_tables_live``) and folded into the fail-closed decision when
``require_live_denylist`` is set (default off), so a token-less load is legible to any caller that
inspects the report or opts into refusing on it.

Loaded lazily from the source checkout; an installed wheel without ``scripts/`` raises a clear error
(the anonymizer is a dev/migration tool, always run from a checkout).
"""

from __future__ import annotations

import importlib.util
import ipaddress
import re
from bisect import bisect_left, bisect_right
from collections import Counter
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from types import ModuleType

from .rules import HEADER_SEGMENTS, AnonError, FieldRule, SurrogateKind, retargeted_defaults
from .surrogates import (
    COMPONENT_KEEPING_KINDS,
    Seps,
    decoded_readings,
    dropped,
    message_has_site_code,
    read_message_seps,
    trim,
    unescape,
    unescaped_fields,
    unescaped_message,
)


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


def _ipv4_allow_list() -> re.Pattern[str] | None:
    """The publish guard's own IPv4 allow list, which the structural IPv6 check uses to judge an
    IPv4-mapped address (BACKLOG #5654), or None when the guard cannot be loaded."""
    try:
        allowed: re.Pattern[str] = _scanner()._ALLOWED_IP
    except LeakCheckUnavailable:
        return None
    return allowed


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


#: A maximal run of hex digits, colons and dots: the text an IPv6 address can be written in. A run
#: with fewer than two colons is skipped, and ``ipaddress`` decides whether the rest hold one. The
#: run is matched whole, never with a colon pinned inside it, so the scan stays linear.
_IPV6_RUN: re.Pattern[str] = re.compile(r"[0-9A-Fa-f.:]+")
#: The IPv6 networks the check allows, as the publish guard allows the private and reserved IPv4
#: ranges: the unspecified and loopback addresses, link-local, unique-local, multicast and the two
#: documentation ranges. They are not routable on the internet, but a unique-local address's
#: Global ID, and a link-local address built from a MAC, can still name a site's network or a
#: device; docs/PHI.md section 9 says so. An IPv4-mapped or IPv4-compatible address is judged by
#: its IPv4 part instead (:func:`_has_routable_ipv6`).
_ALLOWED_IPV6: tuple[ipaddress.IPv6Network, ...] = tuple(
    ipaddress.IPv6Network(net)
    for net in (
        "::/128",
        "::1/128",
        "fe80::/10",
        "fc00::/7",
        "ff00::/8",
        "2001:db8::/32",
        "3fff::/20",
    )
)
#: The deprecated IPv4-compatible block, whose low 32 bits are an IPv4 address.
_IPV4_COMPATIBLE = ipaddress.IPv6Network("::/96")
#: The loopback address, the highest one in :data:`_IPV4_COMPATIBLE` that embeds no IPv4 address.
_IPV6_LOOPBACK = ipaddress.IPv6Address(1)
#: The multicast flag that says the address embeds a unicast prefix (RFC 3306 and the embedded-RP
#: form of RFC 3956), set in bits 116 to 119 of the address.
_MULTICAST_PREFIX_FLAG = 0x2


def _ipv6_candidates(run: str) -> Iterator[str]:
    """The texts in ``run`` an IPv6 address may be written as: the run, without the dots that end
    a sentence, without a trailing ``.port`` or ``.word``, and without both; each of those with one
    colon taken off either end or both, as a label or a list joins one; and each with every colon
    and dot taken off both ends. So ``Addr:::ffff:808:808``, ``IP:2a01:4f8::``,
    ``2a01:4f8::5.443``, ``2a01:4f8::5.443.`` and ``2a01:4f8:::`` still hold their address. A
    text may come more than once. :func:`_label_dropped_runs` gives the texts to try when none of
    these parse."""
    stripped = run.strip(".")
    for base in (run, stripped, run.rsplit(".", 1)[0], stripped.rsplit(".", 1)[0]):
        front = base[1:] if base.startswith(":") else base
        yield from (base, front)
        if base.endswith(":"):
            yield from (base[:-1], front[:-1])
        yield base.strip(":.")


def _label_dropped_runs(run: str) -> tuple[str, ...]:
    """``run`` without a leading label that ends in hex letters or digits and a colon or dot, as
    in ``Device:`` or ``data.``, without a trailing ``:port``, and without both, as in
    ``IPv6:<address>:443``. Tried only when no text :func:`_ipv6_candidates` gives parses, so a
    well-formed address, such as a unique-local ``fd00:1::5``, is never read as the shorter
    address its tail would make."""
    labels = (
        run.split(":", 1)[1] if ":" in run else run,
        run.split(".", 1)[1] if "." in run else run,
    )
    return (*labels, run.rsplit(":", 1)[0], *(label.rsplit(":", 1)[0] for label in labels))


def _is_allowed_ipv6(address: ipaddress.IPv6Address) -> bool:
    """True if ``address`` is in :data:`_ALLOWED_IPV6` and, when it is multicast, does not embed a
    unicast prefix, which can name the site's own network."""
    if address.is_multicast and (int(address) >> 116) & _MULTICAST_PREFIX_FLAG:
        return False
    return any(address in net for net in _ALLOWED_IPV6)


#: The reason a routable IPv6 address gets (BACKLOG #5654).
IPV6_REASON = "routable IPv6 address"


def _has_routable_ipv6(text: str, ipv4_is_routable: Callable[[str], bool]) -> bool:
    """True if ``text`` holds an IPv6 address outside :data:`_ALLOWED_IPV6` (BACKLOG #5654). An
    IPv4-mapped or IPv4-compatible address counts when ``ipv4_is_routable`` says its dotted IPv4
    part is routable, so the IPv4 allow list stays the publish guard's own. Every text
    :func:`_ipv6_candidates` gives is tried, and any one that parses to a routable address is a
    hit, so a fail-closed check refuses on any reading. When none parses, the texts of
    :func:`_label_dropped_runs` are tried the same way. What it misses, and what it refuses
    though it holds no address, is listed in docs/PHI.md section 9."""
    for match in _IPV6_RUN.finditer(text):
        run = match.group()
        if run.count(":") < 2:
            continue
        verdict = _judge_ipv6_texts(_ipv6_candidates(run), ipv4_is_routable)
        if verdict is None:
            dropped = (c for r in _label_dropped_runs(run) for c in _ipv6_candidates(r))
            verdict = _judge_ipv6_texts(dropped, ipv4_is_routable)
        if verdict:
            return True
    return False


def _judge_ipv6_texts(texts: Iterable[str], ipv4_is_routable: Callable[[str], bool]) -> bool | None:
    """True if any of ``texts`` parses to a routable IPv6 address, False if some parse and none is
    routable, and None if none parses. A failed parse means the text is no address, so it is
    skipped, not logged."""
    parsed = False
    for candidate in dict.fromkeys(texts):
        try:
            address = ipaddress.IPv6Address(candidate)
        except ValueError:
            continue  # not an address: the next text is tried
        parsed = True
        embedded = address.ipv4_mapped
        if embedded is None and address in _IPV4_COMPATIBLE and address > _IPV6_LOOPBACK:
            embedded = ipaddress.IPv4Address(int(address))
        if embedded is not None:
            if ipv4_is_routable(str(embedded)):
                return True
        elif not _is_allowed_ipv6(address):
            return True
    return False if parsed else None


def _ipv4_is_routable(ip: str) -> bool:
    """True if the dotted IPv4 ``ip`` is outside the publish guard's own IPv4 allow list
    (:func:`_ipv4_allow_list`), so an IPv4-mapped IPv6 address is judged as the guard judges its
    IPv4 part. With no allow list reachable, every address counts, failing closed."""
    allowed = _ipv4_allow_list()
    return allowed is None or allowed.match(ip) is None


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
#: It names some of the kinds of line the walk refuses; ``normalized_message`` and the tee's run
#: summary quote it. Among those it leaves out are a bare id that is well formed but not defined,
#: and an ``MSH`` line ahead of the header.
MALFORMED_LINE_HIT = (
    "line no rule can reach (kinds include at least a malformed segment id, a header line with "
    "no separator after its encoding characters, and a line with no fields under a header whose "
    "MSH-12 holds no readable HL7 version)"
)
#: The advice that goes with :data:`MALFORMED_LINE_HIT`.
MALFORMED_LINE_ADVICE = (
    "Repair the line no rule can reach: give it a well-formed segment id, or give a header line "
    "the separator after its encoding characters. For a line with no fields under a header whose "
    "MSH-12 holds no readable HL7 version, give the header its real version (the one the sender used), or "
    "map a field of that segment with a rule that rewrites. A rule on MSH-12 does not help: the anonymizer and "
    "anonymize_checked judge the input's version, and a direct leak check judges it when given "
    "version=message_version(raw)."
)
#: The stand-in segment id for a well-formed id that the message's HL7 version does not define and
#: that is not a Z-segment. A segment id is untrusted text too -- a wrapped ``KIM|F`` looks like a
#: segment -- so only a defined id, a Z-segment or an id a rule names is ever printed in an address.
UNKNOWN_SEGMENT = "(unknown segment)"
#: What follows the segment id in the address of a bare line that passed: a line with no field
#: separator whose whole text is an id the message's HL7 version defines or a rule names. That is
#: a legal empty segment, but a wrapped line of free text that is exactly such an id looks the
#: same, so the line gets a coverage record. The address is the segment id, the line's 1-based
#: position among the lines that hold something, and then this marker, as in
#: ``PV2 at line 3 (line with no fields)`` (:func:`_bare_line_address`). The position counts no
#: blank or whitespace-only line, so ``normalized_message`` dropping one does not move it.
#: :class:`CoverageTally` folds the position away and counts each segment id once per
#: message, so a long run keeps one entry per segment id (BACKLOG #3001).
BARE_LINE = " (line with no fields)"


def _bare_line_address(seg_id: str, line: int) -> str:
    """The coverage address of a bare ``seg_id`` line that passed, at 1-based ``line``."""
    return f"{seg_id} at line {line}{BARE_LINE}"


def _is_bare_line(address: str) -> bool:
    """True for a :func:`_bare_line_address`, and for the key :class:`CoverageTally` folds it
    to. No other address ends in :data:`BARE_LINE`: a field address ends in its field number."""
    return address.endswith(BARE_LINE)


def _bare_line_segment(address: str) -> str:
    """The segment id of a :func:`_bare_line_address`; the inverse of its first half."""
    return address.split(" ", 1)[0]


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


def _version_segments(version: str) -> frozenset[str] | None:
    """The segment ids HL7 ``version`` (MSH-12) defines: the newest table at or below it. ``None``
    when the version is not readable: empty, not digits joined by single dots, or older than every
    table. Raises as :func:`_version_key` does."""
    key = _version_key(version)
    chosen: frozenset[str] | None = None
    if key is not None:
        for table_key, ids in _SEGMENT_TABLES:
            if table_key <= key:
                chosen = ids
    return chosen


def known_segments(version: str) -> frozenset[str]:
    """The segment ids HL7 ``version`` (MSH-12) defines: the newest table at or below it. An empty or
    unparseable version, or one older than every table, gets the ids that ANY version defines, which
    names more than the message's own version would. The walk prints a field's address by
    this reading; it judges a bare line by the version's own table alone (BACKLOG #3001). A version with a run
    of more than :data:`_VERSION_PART_MAX_DIGITS` digits raises a body-free :class:`AnonError`."""
    chosen = _version_segments(version)
    return chosen if chosen is not None else _ANY_VERSION_SEGMENTS


#: The fewest split fields a header line (``HEADER_SEGMENTS``) can have: the id, the encoding
#: characters, and one field after them, the first a rule may rewrite. Without it the line's text
#: sits in field 2, which no rule may rewrite, so it would pass through untouched (BACKLOG #2998).
_HEADER_MIN_FIELDS = 3


def _line_is_malformed(fields: list[str], defined: frozenset[str] | set[str]) -> bool:
    """True if no rule can reach this line. Either its first field is not a well-formed segment
    id, or the line has no field separator and its text is not an id in ``defined``.

    A bare ``LEE`` or ``ZOE`` is three
    letters of untrusted text that no rule can address, so it is malformed. ``defined`` is the ids
    the message's HL7 version defines plus the ids a rule names, so a bare ``ZPD`` is an empty
    segment only when a rule names ``ZPD``. A Z-prefix alone does not count (BACKLOG #2247).
    Under a header whose MSH-12 holds no readable version, ``defined`` is the ids a rule names
    alone (BACKLOG #3001).

    A header line (``MSH``, ``FHS``, ``BHS``) is malformed with fewer than
    :data:`_HEADER_MIN_FIELDS` split fields. A bare one carries no separators, and the engine's
    parser refuses it where the tee would emit it. One with no separator after its encoding
    characters (``BHS|TEXT``) holds its text in field 2, which no rule may rewrite, so it would
    pass through untouched (BACKLOG #2998)."""
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
    ``read_message_seps`` takes the separators from, and no other. A header with fewer than
    :data:`_HEADER_MIN_FIELDS` split fields, such as a lone ``MSH|^~\\&``, is not skipped: it is
    refused, like every short header line (BACKLOG #3001). An ``MSH`` line
    ahead of it is not the header: it is walked, and refused whatever it holds, where one after
    the header is refused only when it is bare or short. Every line,
    whichever side of the header it sits on, is judged against the header's own MSH-12 version
    (BACKLOG #3001). A later MSH line is checked. It, and every ``BHS`` and ``FHS`` line, is
    numbered the header way: field N sits at split index N-1, because field 1 is the separator
    itself. Both adapters apply a rule to that same field (BACKLOG #2265, #2998).
    ``mapped_paths`` is occurrence-agnostic (a rule applies to every occurrence of its segment),
    so the address is the bare ``SEG-i``. Returns ``[]`` when the message has no parseable MSH
    (there is no field separator to split on).

    A line whose first field is not a well-formed segment id, or that has no field separator and
    is not an id the message's HL7 version defines or a rule names (a wrapped ``LEE`` looks like a
    segment id), is reported under :data:`MALFORMED_SEGMENT`,
    first field included as index 0, so its text reaches the detectors but never an address.
    :func:`structural_phi_hits` refuses such a line outright. A line holding only whitespace or
    control characters (NUL padding, a trailing SUB) carries nothing and is skipped.

    When the header's MSH-12 holds no readable version (empty, not digits joined by single dots,
    or older than 2.1), at any field count, a bare line may stand only for a segment a rule names;
    any other is refused in the same way. The callers that refuse pass the paths of the rules
    that rewrite as ``mapped_paths``, so a keep does not count. Field addresses still print any
    id some version defines (BACKLOG #3001).

    A bare line that passes gets one record: its segment id, its 1-based position among the lines
    of ``text`` that hold something, and :data:`BARE_LINE`, as in
    ``PV2 at line 3 (line with no fields)``, with an empty value. No rule can rewrite it, so the
    record is there whatever ``mapped_paths`` holds, and :func:`leak_report` decides whether it
    counts as decided (BACKLOG #3001).

    A well-formed id that the header's MSH-12 version does not define, is not a Z-segment and no
    rule names is addressed as :data:`UNKNOWN_SEGMENT`: its fields are still checked, but the id
    itself, which may be a wrapped name, is never printed.

    ``named_by`` is the rule paths whose segment ids count as named, ``mapped_paths`` when left
    out. :func:`past_first_component_hits` walks with fewer paths mapped than the rules name,
    and passes every rule's path here so a segment only those rules name keeps its address.
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
    rule_ids = {path.split("-", 1)[0] for path in naming}
    version_ids = _version_segments(version)
    # The ids a field's address may print. With no readable version that is every version's ids,
    # so the addresses of a versionless message keep their segment ids.
    nameable = (_ANY_VERSION_SEGMENTS if version_ids is None else version_ids) | rule_ids
    # The ids a bare line may stand for. With no readable version, only an id a rule names: the
    # union of every version would let a bare ``SFT`` through a 2.3 message (BACKLOG #3001).
    defined = rule_ids if version_ids is None else nameable
    # The 1-based position of a line among those that hold something, as a bare line's record
    # gives it. ``normalized_message`` drops the others, so a capture and its output agree.
    position = 0
    for n, seg in enumerate(lines):
        if all(c.isspace() or not c.isprintable() for c in seg):
            continue
        position += 1
        fields = seg.split(field_sep)
        seg_id = fields[0]
        is_msh = seg_id.upper() == "MSH"
        # A header whose separator is a letter of its own id does not split to an MSH id. It is
        # not skipped, and the check below refuses it, as it did before the header was found
        # by line. Nor is a header below _HEADER_MIN_FIELDS (a lone ``MSH|^~\&``): the check
        # below refuses it, as it refuses every short header line (BACKLOG #3001).
        if n == header_at and is_msh and len(fields) >= _HEADER_MIN_FIELDS:
            continue
        # One address per split index; None for a field the check does not judge.
        addresses: list[str | None]
        # An MSH line ahead of the header is refused whatever it holds. The tee adapter takes
        # the FIRST line whose id reads MSH as its header, so with one here an MSH rule would
        # miss the real header, which this walk never checks.
        if _line_is_malformed(fields, defined) or (n < header_at and is_msh):
            # Index 0 is _MALFORMED_LINE, recorded even when empty.
            addresses = [f"{MALFORMED_SEGMENT}-{i}" for i in range(len(fields))]
        elif len(fields) == 1:
            # A bare id that passed is in ``defined``, so it is safe to print. The value is
            # empty: the id is all the line holds, and an empty value trips no detector.
            out.append((_bare_line_address(seg_id, position), ""))
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
            split_hits.extend(_split_shape_hits(fields, seps, field_sep, addresses))
    return out, split_hits


def _line_readings(fields: list[str], seps: Seps, field_sep: str) -> list[list[str]]:
    """The fields of one line as written, then with each field decoded a subcomponent at a time
    and a component at a time, the readings :func:`unescaped_message` gives the token scan. The
    segment id and encoding characters of a header line are left as written. A reading the same
    as one before it is left out."""
    readings = [fields]
    if not seps.escape or not any(seps.escape in field for field in fields):
        return readings
    for by_component in (False, True):
        decoded = unescaped_fields(fields, seps, field_sep, by_component=by_component)
        if decoded not in readings:
            readings.append(decoded)
    return readings


def _split_shape_hits(
    fields: list[str], seps: Seps, field_sep: str, addresses: Sequence[str | None]
) -> list[str]:
    """Hits for a punctuated shape (:data:`_SPLITTABLE_SHAPES`) that the field separator cuts
    across the ``fields`` of one line: a match on the line that runs across a separator between
    two fields, so no one field held it whole (BACKLOG #3465). Under ``|`` no such match exists.

    The line is read as written and with its fields decoded (:func:`_line_readings`), so a shape
    whose own characters are escaped, such as ``123-45\\X2D\\6789`` under a field separator of
    ``-``, is found too (#5533 item 8). A separator is only where the fields meet, so a field
    separator a ``\\F\\`` decodes to inside a field never counts as a cut; the shape detectors
    that read one field judge that one.

    ``addresses`` names each split index of the line, ``None`` for a field the check does not
    judge. A match is a hit when at least one field it reaches has an address, and the hit names
    the first and last of those. So a match that starts in a field a rule rewrote is a hit when it
    runs on into a field no rule rewrites: the shape reached the output whole. What still passes
    is listed once, in docs/PHI.md section 9."""
    hits: list[str] = []
    for reading in _line_readings(fields, seps, field_sep):
        line = field_sep.join(reading)
        # Where each separator between two fields sits in ``line``, found once per reading, so a
        # long line costs a search per match, not a rescan.
        cuts: list[int] = []
        at = -1
        for field in reading[:-1]:
            at += len(field) + 1
            cuts.append(at)
        for pattern, reason in _SPLITTABLE_SHAPES:
            for match in pattern.finditer(line):
                if bisect_left(cuts, match.start()) == bisect_left(cuts, match.end()):
                    continue  # no separator inside the match: one field held it whole
                # The fields that hold a character of the match: the separators at or before its
                # first character, and those before its last. A separator at its first character
                # belongs to no field, so counting it starts at the next field.
                first = bisect_right(cuts, match.start())
                last = bisect_left(cuts, match.end() - 1)
                named = [a for a in addresses[first : last + 1] if a is not None]
                if named:
                    span = named[0] if len(named) == 1 else f"{named[0]} to {named[-1]}"
                    hit = f"{reason} across {span}, cut by the field separator"
                    # A decoded reading adds only what the reading as written did not find.
                    if reading is fields or hit not in hits:
                        hits.append(hit)
    return hits


def _decoded_parts(value: str, seps: Seps, field_sep: str) -> Iterator[str]:
    """Each component of ``value`` that holds the escape character, decoded whole, and each of its
    subcomponents that holds one, decoded on its own. Those are the two readings the engine gives
    a part: ``Message`` decodes a whole component on a component read and one subcomponent on a
    subcomponent read, and ``Peek`` decodes a subcomponent. A part is decoded after the split, so
    an escaped separator inside it never makes a new one. A part with no escape character is left
    out: the raw scan of the whole value already read it."""
    if not seps.escape or seps.escape not in value:
        return
    for rep in value.split(seps.repetition):
        for comp in rep.split(seps.component):
            if seps.escape not in comp:
                continue
            yield unescape(comp, seps, field_sep)
            if seps.subcomponent in comp:
                for leaf in comp.split(seps.subcomponent):
                    if seps.escape in leaf:
                        yield unescape(leaf, seps, field_sep)


def _merged_token_hits(scan: Callable[[str], list[str]], text: str) -> list[str]:
    """``scan`` run over ``text`` as written, then over :func:`unescaped_message` decoded a
    subcomponent at a time and a component at a time, so a token written with an HL7 escape
    sequence is found in either reading (BACKLOG #5532). A decoding that matches one already
    scanned is not scanned again, and a reason a later pass finds again is not repeated."""
    hits = scan(text)
    scanned = {text}
    for by_component in (False, True):
        decoded = unescaped_message(text, by_component=by_component)
        if decoded not in scanned:
            scanned.add(decoded)
            hits.extend(hit for hit in scan(decoded) if hit not in hits)
    return hits


def _has_mrn_typed_identifier(value: str, seps: Seps, field_sep: str) -> bool:
    """True if any repetition of ``value`` has a non-empty component 1 and an ``MR``/``MRN`` id
    type — an unmapped medical-record number by HL7 structure, far more precise than a bare
    digit-run heuristic. Two readings count (BACKLOG #5654):

    * any component, component 1 included, that is ``MR`` or ``MRN`` whole or as its first
      subcomponent, as written or decoded and trimmed, so ``12345^MR``, ``MRN^12345``,
      ``12345^MR&L`` and an XCN ``1234^DOE^JOHN^^^MR`` count, as they did before; and
    * CX.5, the identifier type code, in any of its subcomponents too, as written or decoded and
      trimmed, so ``ID^^^AUTH^MR&local`` counts.

    ``M\\X52\\`` (BACKLOG #5532) and ``MR\\X20\\`` count in either. A decoded part is never split
    again, so ``PET&MR`` outside CX.5, and a word ``MR`` that an escaped delimiter or whitespace
    sets apart, as in ``PET\\T\\MR`` or ``X\\S\\MR``, do not count. :func:`.surrogates.trim`
    says what is trimmed. The id counts when it is non-empty as written, so one that decodes to
    nothing, such as ``\\Z98765\\``, counts."""
    for rep in value.split(seps.repetition):
        comps = rep.split(seps.component)
        if not comps[0]:
            continue
        if any(_is_mrn_type(comp, seps, field_sep, subcomponents=False) for comp in comps):
            return True
        if len(comps) >= 5 and _is_mrn_type(comps[4], seps, field_sep, subcomponents=True):
            return True
    return False


def _is_mrn_type(comp: str, seps: Seps, field_sep: str, *, subcomponents: bool) -> bool:
    """True if ``comp`` is ``MR`` or ``MRN`` as written or decoded whole, as a ``Message`` component
    read decodes it, or as its first subcomponent, as ``Peek`` reads a component that has them,
    each reading also with its invisible characters dropped (:func:`.surrogates.dropped`), each
    trimmed (:func:`.surrogates.trim`), and never split again. With ``subcomponents``, any one of
    its subcomponents counts the same way, since a ``Message`` subcomponent read can read any of
    them (BACKLOG #5654)."""
    leaves = comp.split(seps.subcomponent)
    if len(leaves) == 1:
        parts: tuple[str, ...] = (comp,)
    else:
        parts = (comp, *leaves) if subcomponents else (comp, leaves[0])
    forms = [
        form
        for part in parts
        for form in (
            part,
            dropped(part),
            *decoded_readings(part, seps, field_sep, resplit=False),
        )
    ]
    return any(trim(form).upper() in _MRN_TYPES for form in forms)


def _structural_reasons(value: str, seps: Seps, field_sep: str) -> list[str]:
    """PHI-safe shape labels for one unmapped field value — the SHAPE only, never the value.

    Each shape is looked for in the value as written and in each of its parts decoded
    (:func:`_decoded_parts`), so a shape written with HL7 escape sequences, such as
    ``123\\X2D\\45\\X2D\\6789``, is found too (BACKLOG #5532). A routable IPv6 address is looked
    for the same way (:func:`_has_routable_ipv6`). It is read here, in a field no rule rewrote, and
    not over the whole message, so a surrogate the anonymizer wrote, such as an id whose letters
    came out as hex beside a ``::``, is never refused as one (BACKLOG #5654)."""
    reasons: list[str] = []
    forms = [value, *_decoded_parts(value, seps, field_sep)]
    for pattern, reason in _SPLITTABLE_SHAPES:
        if reason not in reasons and any(pattern.search(form) for form in forms):
            reasons.append(reason)
    if _has_mrn_typed_identifier(value, seps, field_sep):
        reasons.append("unmapped MRN-typed identifier")
    if any(_has_routable_ipv6(form, _ipv4_is_routable) for form in forms):
        reasons.append(f"unmapped {IPV6_REASON}")
    return reasons


def _header_ipv6_hits(text: str, mapped_paths: set[str]) -> list[str]:
    """Routable-IPv6 hits in the header, the one line :func:`_walk` skips: each field from MSH-3
    on that no rule rewrites, read as written and decoded as :func:`_structural_reasons` reads a
    value. The whole-message IPv4 check reads the header, so an IPv6 address there, such as one
    in MSH-24, is judged too (BACKLOG #5654). Only the IPv6 shape is read here. MSH-1 and MSH-2
    hold the delimiters and are never read. A header the walk does not skip, such as a short one,
    is walked and judged there, so it is not read again."""
    found = _split_at_header(text)
    if found is None:
        return []
    seps, field_sep, lines, header_at = found
    fields = lines[header_at].split(field_sep)
    if fields[0].upper() != "MSH" or len(fields) < _HEADER_MIN_FIELDS:
        return []
    hits: list[str] = []
    # fields[1] is MSH-2, the encoding characters, so fields[i] is MSH-(i + 1).
    for number, value in enumerate(fields[2:], start=3):
        address = f"MSH-{number}"
        if not value or address in mapped_paths:
            continue
        forms = [value, *_decoded_parts(value, seps, field_sep)]
        if any(_has_routable_ipv6(form, _ipv4_is_routable) for form in forms):
            hits.append(f"unmapped {IPV6_REASON} in {address}")
    return hits


def structural_phi_hits(
    text: str, mapped_paths: set[str], *, version: str | None = None
) -> list[str]:
    """Structural PHI-shape hits over the fields no rule matched — reasons name the shape + field
    ADDRESS only (e.g. ``"unmapped SSN-shaped value in ZPD-4"``), never the offending value, so the
    result is safe to raise/log. Empty when the message has no parseable MSH. ``version`` is
    handed to the walk behind :func:`unmapped_field_values`.

    A line no rule can reach (kinds include at least a malformed segment id, a short header line,
    and a bare line under a header with no readable version; see :func:`_line_is_malformed`) is a
    hit by itself, whatever it holds: the anonymizer passed it through untouched, and a wrapped
    name or note is exactly what such a line tends to carry.

    A dashed SSN or punctuated phone that the message's own field separator cuts across fields
    is a hit too, named by the fields it spans (:func:`_split_shape_hits`, BACKLOG #3465).

    The header, which the walk skips, is read for a routable IPv6 address alone
    (:func:`_header_ipv6_hits`, BACKLOG #5654)."""
    parsed = read_message_seps(text)
    if parsed is None:
        return []
    seps, field_sep = parsed
    hits: list[str] = []
    walked, split_hits = _walk(text, mapped_paths, version, split=True)
    for address, value in walked:
        if address == _MALFORMED_LINE:
            hits.append(MALFORMED_LINE_HIT)
        hits.extend(
            f"{reason} in {address}" for reason in _structural_reasons(value, seps, field_sep)
        )
    return _header_ipv6_hits(text, mapped_paths) + hits + split_hits


#: What a hit in the part of a field a retarget left reads as, after its shape label.
RETARGET_RESIDUE = "left by a retarget"
#: What a hit in a component an identifier rule kept reads as, after its shape label.
KEPT_COMPONENT = "in a component an identifier rule keeps"


def past_first_component_hits(
    text: str, rules: tuple[FieldRule, ...], *, version: str | None = None
) -> list[str]:
    """Structural PHI-shape hits in the part past component 1 of a mapped field that a rule can
    leave as captured. Reasons name the shape and the field address only, never a value.

    A rule maps its field, so :func:`structural_phi_hits` never scans it. Two kinds of field
    are scanned here, each repetition with its component 1 left out, for the dashed SSN, the
    punctuated phone and a routable IPv6 address (BACKLOG #5654), as written and decoded as
    :func:`_structural_reasons` reads a value:

    * a default field a retarget points at a different kind (:func:`.rules.retargeted_defaults`,
      BACKLOG #3493). Its hits read :data:`RETARGET_RESIDUE`, unless its default kind is one
      of the identifier kinds below, which would keep the same components.
    * every other field an ``id``, ``mrn``, ``ssn`` or ``dln`` rule rewrites
      (:data:`.surrogates.COMPONENT_KEEPING_KINDS`), whose surrogate keeps the issuer components
      as the sender wrote them (BACKLOG #5533, #5534). Its hits read :data:`KEPT_COMPONENT`.

    The MRN-typed shape needs a component 1, so it never fires here, which is right: the id
    there is the surrogate. The other kinds add no hit on a retargeted field: ``name``,
    ``address`` and ``provider`` write values from fixed pools, and
    ``tests/test_anon_overlay_retarget_warning.py`` pins that no pool value has the SSN or phone
    shape. Nothing pins that no pool value reads as an IPv6 address, so a pool value written as
    a hex word beside ``::`` would make a retarget refuse its own output. ``phone`` and ``dob``
    write one component; ``date`` writes component 1 and keeps after
    it only a known TS.2 precision code.

    The walk names a segment by every rule's path, so a segment only these rules name keeps its
    address in a message whose HL7 version does not define it."""
    retargets = retargeted_defaults(rules)
    # A retarget away from an identifier kind is labelled as one. From one identifier kind to
    # another, the default kind keeps components too, so pointing the field back would not
    # clear the hit: it reads as a kept component, with that advice.
    residue = {d.path for d, _ in retargets if d.kind not in COMPONENT_KEEPING_KINDS}
    keeping = {r.path for r in rules if r.kind in COMPONENT_KEEPING_KINDS}
    paths = {d.path for d, _ in retargets} | keeping
    parsed = read_message_seps(text)
    if not paths or parsed is None:
        return []
    seps, field_sep = parsed
    rewritten = {r.path for r in rules if r.kind != SurrogateKind.KEEP}
    hits: list[str] = []
    walk = unmapped_field_values(text, rewritten - paths, version=version, named_by=rewritten)
    for address, value in walk:
        if address not in paths:
            continue
        label = RETARGET_RESIDUE if address in residue else KEPT_COMPONENT
        rest = seps.repetition.join(
            seps.component.join(["", *rep.split(seps.component)[1:]])
            for rep in value.split(seps.repetition)
        )
        hits.extend(
            f"{reason.removeprefix('unmapped ')} {label} in {address}"
            for reason in _structural_reasons(rest, seps, field_sep)
        )
    return hits


def retarget_residue_hits(
    text: str, rules: tuple[FieldRule, ...], *, version: str | None = None
) -> list[str]:
    """The hits of :func:`past_first_component_hits` in what a retarget of a default field left
    (BACKLOG #3493)."""
    hits = past_first_component_hits(text, rules, version=version)
    return [hit for hit in hits if RETARGET_RESIDUE in hit]


def kept_component_hits(
    text: str, rules: tuple[FieldRule, ...], *, version: str | None = None
) -> list[str]:
    """The hits of :func:`past_first_component_hits` in the components an ``id``, ``mrn``,
    ``ssn`` or ``dln`` rule kept, on a field no retarget names (BACKLOG #5533, #5534)."""
    hits = past_first_component_hits(text, rules, version=version)
    return [hit for hit in hits if KEPT_COMPONENT in hit]


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
    detectors run over those fields, over what a retarget of a default field left past its
    first component (:func:`retarget_residue_hits`), and over the components an identifier rule
    keeps past its first (:func:`kept_component_hits`). With ``rules is None`` (a direct/legacy
    call over a bare string) structural detection is skipped and the check is token-only, as the
    legacy one was, except that the token scan also reads the text decoded from its HL7 escape
    sequences when it has a parseable MSH (BACKLOG #5532), so it can name a token the legacy check
    missed.

    ``version`` is the HL7 version a bare line is judged by. A caller that checks the OUTPUT of
    ``anonymize`` passes the version of the INPUT (:func:`message_version`), because a rule may
    have rewritten MSH-12. Left out, the version is read from ``text`` (BACKLOG #3004).
    """
    scanner = _scanner()
    # Over the text as written and decoded, so an escaped token is found too (BACKLOG #5532).
    token_hits = _merged_token_hits(
        lambda body: [str(h) for h in scanner.scan_text(body, include_estate=True)], text
    )
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
        structural += past_first_component_hits(text, rules, version=version)
        decided = {r.path for r in rules}
        # A bare line has no field a rule could name, so a rule or a keep on ANY field of its
        # segment decides it (BACKLOG #3001).
        decided_segments = {path.split("-", 1)[0] for path in decided}
        parsed = read_message_seps(text)
        seps = parsed[0] if parsed is not None else Seps()
        undecided = tuple(
            sorted(
                {
                    address
                    for address, value in unmapped_field_values(text, decided, version=version)
                    if not (
                        _is_bare_line(address) and _bare_line_segment(address) in decided_segments
                    )
                    and not _decided_by_shape(address, value, seps)
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
    matched, to what a retarget left and to the components an identifier rule keeps; omitting it
    (a bare-string call) runs the token-only check :func:`leak_report` describes. A caller that ran
    ``anonymize`` itself
    passes ``version=message_version(raw)``, as :func:`leak_report` says.
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
#: What to do about a hit in a component an identifier rule kept. The field is already mapped, so
#: extending the rule map does not help, and a keep would leave the whole field instead.
KEPT_COMPONENT_ADVICE = (
    "Point each field whose kept identifier components carry it at drop or freetext in an overlay."
)
#: The advice for each kind of hit in a mapped field (:func:`past_first_component_hits`), by the
#: label its hits carry. Such a hit is no reason to extend the rule map: the field is mapped.
_MAPPED_FIELD_ADVICE: tuple[tuple[str, str], ...] = (
    (RETARGET_RESIDUE, RETARGET_ADVICE),
    (KEPT_COMPONENT, KEPT_COMPONENT_ADVICE),
)


def mapped_field_advice(report: LeakReport) -> list[str]:
    """The advice for each kind of hit in a mapped field that ``report`` holds
    (:func:`past_first_component_hits`), in a fixed order. Empty when it holds none. A keep is
    the wrong advice for every one of them: it would leave the whole field."""
    return [
        advice
        for label, advice in _MAPPED_FIELD_ADVICE
        if any(label in hit for hit in report.structural_hits)
    ]


def has_other_cause(report: LeakReport) -> bool:
    """True if ``report`` holds a hit that is not in a mapped field, such as a token or a shape
    in a field no rule maps, so its fix is not only the advice :func:`mapped_field_advice`
    gives."""
    return any(not any(label in hit for label, _ in _MAPPED_FIELD_ADVICE) for hit in report.hits)


def refusal_advice(
    report: LeakReport, *, denylist_refused: bool = False, coverage_refused: bool = False
) -> str:
    """What to do about a refusal: one sentence per KIND of cause that fired, and no others.
    Every refusal used to suggest repairing a malformed line, even when a token was the cause
    (BACKLOG #2247). PHI-safe: fixed text, chosen by the kind of hit and never by a value."""
    steps: list[str] = []
    token_hit = len(report.hits) > len(report.structural_hits)
    shape_hit = any(
        hit != MALFORMED_LINE_HIT and not any(label in hit for label, _ in _MAPPED_FIELD_ADVICE)
        for hit in report.structural_hits
    )
    if token_hit or shape_hit:
        steps.append("Extend the rule map so the field that carries it is scrubbed.")
    steps.extend(mapped_field_advice(report))
    if coverage_refused:
        steps.append("Add a rule for each field named, or a keep for one you reviewed.")
        if any(_is_bare_line(address) for address in report.undecided_fields):
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
    "Beyond the partner-token and IPv4 scan of the whole message, the leak-check looks in these "
    "fields only for a dashed SSN, a punctuated phone number, an MR/MRN-typed identifier and a "
    "routable IPv6 address. A "
    "name, an undashed number or a date in one of them passes, so review this list before you "
    "share the dataset."
)


def _tally_key(address: str) -> str:
    """``address`` as :class:`CoverageTally` counts it: a bare line by its segment id alone."""
    return f"{_bare_line_segment(address)}{BARE_LINE}" if _is_bare_line(address) else address


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
        # A bare line's position is folded away: line 3 of one message and line 3 of the next
        # are different lines, and the per-message report keeps the position (BACKLOG #3001).
        # Once per message, as every other address is counted.
        self.counts.update({_tally_key(address) for address in report.unmapped_fields})
        self.undecided.update({_tally_key(address) for address in report.undecided_fields})
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
        if any(_is_bare_line(address) for address in self.counts):
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
