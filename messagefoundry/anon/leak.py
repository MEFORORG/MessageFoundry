# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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
  punctuated NANP phone, CX ``MR``/``MRN``-typed identifier) — narrow by design to avoid the mass
  false-positives a broad digit-run search would produce on HL7 bodies (ADR 0030 §5).

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
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from types import ModuleType

from .rules import FieldRule
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


def unmapped_field_values(text: str, mapped_paths: set[str]) -> list[tuple[str, str]]:
    """Every ``(address, value)`` in ``text`` whose whole-field ``SEG-i`` address is **not** in
    ``mapped_paths`` and whose value is non-empty — the fields the rule map never touched.

    The MSH control header is skipped whole: its field indexing is off-by-one (MSH-N sits at
    split-index N-1) and it carries routing/site data the field-anchored site-code pass already
    covers, not patient PHI. ``mapped_paths`` is occurrence-agnostic (a rule applies to every
    occurrence of its segment), so the address is the bare ``SEG-i``. Returns ``[]`` when the message
    has no parseable MSH (there is no field separator to split on).
    """
    parsed = read_message_seps(text)
    if parsed is None:
        return []
    _seps, field_sep = parsed
    out: list[tuple[str, str]] = []
    for seg in text.replace("\r\n", "\r").replace("\n", "\r").split("\r"):
        if not seg:
            continue
        fields = seg.split(field_sep)
        if fields[0].upper() == "MSH":
            continue
        seg_id = fields[0]
        for i in range(1, len(fields)):
            value = fields[i]
            if not value:
                continue
            address = f"{seg_id}-{i}"
            if address in mapped_paths:
                continue
            out.append((address, value))
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
    result is safe to raise/log. Empty when the message has no parseable MSH."""
    parsed = read_message_seps(text)
    if parsed is None:
        return []
    seps, _field_sep = parsed
    hits: list[str] = []
    for address, value in unmapped_field_values(text, mapped_paths):
        hits.extend(f"{reason} in {address}" for reason in _structural_reasons(value, seps))
    return hits


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
    """

    hits: list[str]
    unmapped_fields: tuple[str, ...]
    structural_hits: list[str]
    token_tables_live: bool
    token_floor_reason: str | None


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
    if rules is None:
        unmapped: tuple[str, ...] = ()
        structural: list[str] = []
    else:
        mapped_paths = {r.path for r in rules}
        unmapped = tuple(sorted({addr for addr, _ in unmapped_field_values(text, mapped_paths)}))
        structural = structural_phi_hits(text, mapped_paths)
    token_tables_live = bool(scanner.TOKENS_PRESENT)
    token_floor_reason: str | None = scanner.token_floor_failure()
    return LeakReport(
        hits=token_hits + structural,
        unmapped_fields=unmapped,
        structural_hits=structural,
        token_tables_live=token_tables_live,
        token_floor_reason=token_floor_reason,
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
