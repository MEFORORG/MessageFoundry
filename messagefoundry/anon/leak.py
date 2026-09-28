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
  malformed) — narrow by design to avoid the mass false-positives a broad digit-run search would
  produce on HL7 bodies (ADR 0030 §5). A name, an undashed number or a date in an unmapped field
  is NOT detected; the coverage report is the only record of it (BACKLOG #1710).

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
from collections import Counter
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from types import ModuleType

from .rules import FieldRule, SurrogateKind
from .surrogates import Seps, message_has_site_code, read_message_seps


class LeakCheckUnavailable(RuntimeError):
    """The publish-guard scanner could not be located (not run from a source checkout)."""


@lru_cache(maxsize=1)
def _scanner() -> ModuleType:
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "scripts" / "security" / "scan_forbidden.py"
        if candidate.is_file():
            spec = importlib.util.spec_from_file_location("mefor_anon_scan_forbidden", candidate)
            if spec is not None and spec.loader is not None:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                return module
    raise LeakCheckUnavailable(
        "could not locate scripts/security/scan_forbidden.py — the anonymizer leak-check requires "
        "the source checkout (it is a dev/migration tool, not an installed-wheel runtime)"
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
#: The stand-in segment id for a well-formed id that the message's HL7 version does not define and
#: that is not a Z-segment. A segment id is untrusted text too -- a wrapped ``KIM|F`` looks like a
#: segment -- so only a defined id, a Z-segment or an id a rule names is ever printed in an address.
UNKNOWN_SEGMENT = "(unknown segment)"

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


def _version_key(version: str) -> tuple[int, ...] | None:
    parts = version.strip().split(".")
    if not all(part.isdigit() for part in parts):
        return None
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
    names more than the message's own version would."""
    key = _version_key(version)
    chosen: frozenset[str] | None = None
    if key is not None:
        for table_key, ids in _SEGMENT_TABLES:
            if table_key <= key:
                chosen = ids
    return chosen if chosen is not None else _ANY_VERSION_SEGMENTS


def unmapped_field_values(text: str, mapped_paths: set[str]) -> list[tuple[str, str]]:
    """Every ``(address, value)`` in ``text`` whose whole-field ``SEG-i`` address is **not** in
    ``mapped_paths`` and whose value is non-empty — the fields the rule map never touched.

    The MSH control header -- the FIRST MSH line only -- is skipped whole: it carries routing/site
    data the field-anchored site-code pass already covers, not patient PHI. A later MSH line is
    checked, and numbered the MSH way (MSH-N sits at split-index N-1). ``mapped_paths`` is occurrence-agnostic (a rule applies to every
    occurrence of its segment), so the address is the bare ``SEG-i``. Returns ``[]`` when the message
    has no parseable MSH (there is no field separator to split on).

    A line whose first field is not a well-formed segment id, or that has no field separator at
    all (a wrapped ``LEE`` looks like a segment id), is reported under :data:`MALFORMED_SEGMENT`,
    first field included as index 0, so its text reaches the detectors but never an address.
    :func:`structural_phi_hits` refuses such a line outright. A line holding only whitespace or
    control characters (NUL padding, a trailing SUB) carries nothing and is skipped.

    A well-formed id that the header's MSH-12 version does not define, is not a Z-segment and no
    rule names is addressed as :data:`UNKNOWN_SEGMENT`: its fields are still checked, but the id
    itself, which may be a wrapped name, is never printed.
    """
    parsed = read_message_seps(text)
    if parsed is None:
        return []
    seps, field_sep = parsed
    out: list[tuple[str, str]] = []
    header_seen = False
    nameable = _ANY_VERSION_SEGMENTS | {path.split("-", 1)[0] for path in mapped_paths}
    for seg in text.replace("\r\n", "\r").replace("\n", "\r").split("\r"):
        if all(c.isspace() or not c.isprintable() for c in seg):
            continue
        fields = seg.split(field_sep)
        if not header_seen and fields[0].upper() == "MSH":
            header_seen = True
            version = fields[11].split(seps.component)[0] if len(fields) > 11 else ""
            nameable = known_segments(version) | {p.split("-", 1)[0] for p in mapped_paths}
            continue
        seg_id = fields[0]
        if len(fields) == 1 or not _SEGMENT_ID.fullmatch(seg_id):
            out.append((_MALFORMED_LINE, seg_id))  # always present, even when empty
            out.extend((f"{MALFORMED_SEGMENT}-{i}", v) for i, v in enumerate(fields) if i and v)
            continue
        named = seg_id if seg_id in nameable or seg_id.startswith("Z") else UNKNOWN_SEGMENT
        shift = 1 if seg_id == "MSH" else 0  # a later MSH: MSH-1 is the separator itself
        for i in range(1, len(fields)):
            value = fields[i]
            if not value or f"{seg_id}-{i + shift}" in mapped_paths:
                continue
            out.append((f"{named}-{i + shift}", value))
    return out


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
    if _SSN_DASHED.search(value):
        reasons.append("unmapped SSN-shaped value")
    if _PHONE_DASHED.search(value) or _PHONE_PAREN.search(value):
        reasons.append("unmapped phone-shaped value")
    if _has_mrn_typed_identifier(value, seps):
        reasons.append("unmapped MRN-typed identifier")
    return reasons


def structural_phi_hits(text: str, mapped_paths: set[str]) -> list[str]:
    """Structural PHI-shape hits over the fields no rule matched — reasons name the shape + field
    ADDRESS only (e.g. ``"unmapped SSN-shaped value in GT1-16"``), never the offending value, so the
    result is safe to raise/log. Empty when the message has no parseable MSH.

    A line with a malformed segment id is a hit by itself, whatever it holds: no rule can reach it,
    so the anonymizer passed it through untouched, and a wrapped name or note is exactly what such a
    line tends to carry."""
    parsed = read_message_seps(text)
    if parsed is None:
        return []
    seps, _field_sep = parsed
    hits: list[str] = []
    for address, value in unmapped_field_values(text, mapped_paths):
        if address == _MALFORMED_LINE:
            hits.append("line with a malformed segment id, which no rule can reach")
        hits.extend(f"{reason} in {address}" for reason in _structural_reasons(value, seps))
    return hits


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
      :data:`ALWAYS_DECIDED` does not excuse; ``require_full_coverage`` refuses on them.
    """

    hits: list[str]
    unmapped_fields: tuple[str, ...]
    structural_hits: list[str]
    token_tables_live: bool
    token_floor_reason: str | None
    undecided_fields: tuple[str, ...] = ()


def leak_report(text: str, *, rules: tuple[FieldRule, ...] | None = None) -> LeakReport:
    """The full :class:`LeakReport` for ``text`` using the publish-guard's token authority.

    Token hits use the guard's substring + estate-token mode (ADR 0030 §5) plus a field-anchored
    site-code check. Structural detection engages **only when ``rules`` is supplied** — the address
    of every unmapped field is derived from ``{r.path for r in rules}`` and the high-precision
    detectors run over those fields. With ``rules is None`` (a direct/legacy call over a bare string)
    structural detection is skipped and the result is byte-for-byte the legacy token-only behaviour.
    """
    scanner = _scanner()
    token_hits = [str(h) for h in scanner.scan_text(text, include_estate=True)]
    if message_has_site_code(text):
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
        unmapped = tuple(sorted({addr for addr, _ in unmapped_field_values(text, mapped_paths)}))
        structural = structural_phi_hits(text, mapped_paths)
        decided = {r.path for r in rules}
        parsed = read_message_seps(text)
        seps = parsed[0] if parsed is not None else Seps()
        undecided = tuple(
            sorted(
                {
                    address
                    for address, value in unmapped_field_values(text, decided)
                    if not _decided_by_shape(address, value, seps)
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


def leak_check(text: str, *, rules: tuple[FieldRule, ...] | None = None) -> list[str]:
    """Forbidden-token + structural PHI hits in ``text`` (empty list = clean) — a thin wrapper over
    :func:`leak_report`. ``rules`` scopes the structural PHI-shape detectors to the fields no rule
    matched; omitting it (a bare-string call) runs the legacy token-only check.
    """
    return leak_report(text, rules=rules).hits


def coverage_clause(report: LeakReport) -> str:
    """A PHI-safe suffix for a fail-closed message naming what the check reached — the count and
    ADDRESSES of the unmapped fields (never their values) and whether the denylist tables were live."""
    live = "yes" if report.token_tables_live else "no"
    fields = ", ".join(report.unmapped_fields) if report.unmapped_fields else "none"
    return (
        f" (checked {len(report.unmapped_fields)} unmapped field(s): {fields}; "
        f"denylist tables live: {live})"
    )


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
    Pass :meth:`add` as ``anonymize_checked``'s ``on_report``."""

    def __init__(self, *, full_coverage: bool = False) -> None:
        self.messages = 0
        self.counts: Counter[str] = Counter()
        self.undecided: Counter[str] = Counter()
        self.full_coverage = full_coverage
        self.denylist_live = True

    def add(self, report: LeakReport) -> None:
        self.messages += 1
        self.counts.update(report.unmapped_fields)
        self.undecided.update(report.undecided_fields)
        self.denylist_live = self.denylist_live and report.token_tables_live

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
        return text
