# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Leak-check for the standalone tee (ADR 0030 §5) — a thin front-end over the publish-guard authority.

The token tables (customer/partner names + estate-vendor tokens) are the owner-managed
``scripts/security/scan_forbidden.py`` set; this file **loads them from that guard by path at import**
(the same way ``messagefoundry/anon/leak.py`` does) rather than vendoring a copy — so **no literal or
fragmented customer/vendor token appears in this tracked, published file**, and there is nothing to
drift (``test_anon_parity`` still pins the two equal). Loading by path keeps the tee ``messagefoundry``-free.

The real tokens themselves are EXTERNALIZED out of the guard (a git-ignored token file /
``MEFOR_FORBIDDEN_TOKENS``), so a token-less checkout (a fork, or an installed wheel with no
``scripts/``) loads the name + estate + site-code tables **empty** and the leak-check degrades to a
no-op for those (a public checkout has no customer estate to leak). The generic IP detector keeps a
literal default so the anonymizer's structural IP check still functions without a token source.

Returns **reasons only** (never the matched text), and the token denylist is the fail-closed
*backstop*, not the primary control: it catches known *tokens*, not structural PHI (ADR 0030 §5). The
structural PHI-shape detectors + unmapped-field coverage report below (BACKLOG #331) close that gap —
they are held byte-for-byte identical with the engine copy so the two agree on every input.
"""

from __future__ import annotations

import importlib.util
import re
from dataclasses import dataclass
from pathlib import Path

from .rules import FieldRule
from .surrogates import Seps, message_has_site_code, read_message_seps


def _load_publish_guard(_start: Path | None = None) -> object | None:
    """Load the owner-managed guard (``scripts/security/scan_forbidden.py``) by path, walking up from
    this file. It is the SINGLE source for the token tables, so none live literally here. Absent from an
    installed wheel with no ``scripts/`` → returns ``None`` and the tables load empty. ``_start``
    overrides the search origin for tests."""
    origin = (_start if _start is not None else Path(__file__)).resolve()
    for parent in origin.parents:
        candidate = parent / "scripts" / "security" / "scan_forbidden.py"
        if candidate.exists():
            spec = importlib.util.spec_from_file_location("tee_anon_publish_guard", candidate)
            if spec is not None and spec.loader is not None:
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                return mod
    return None


_GUARD = _load_publish_guard()

# Customer/partner names + estate-vendor tokens — sourced from the publish guard (held identical to it
# by test_anon_parity), so NO literal or fragmented customer/vendor token appears in this published
# file. Empty when the guard is absent (the OSS mirror), where the leak-check is a no-op for these.
FORBIDDEN: list[tuple[re.Pattern[str], str]] = list(_GUARD.FORBIDDEN) if _GUARD else []  # type: ignore[attr-defined]
ESTATE_TOKENS: tuple[str, ...] = tuple(_GUARD.ESTATE_TOKENS) if _GUARD else ()  # type: ignore[attr-defined]

# Generic structural detectors (NOT customer data): loaded from the guard when present (parity), with a
# literal default so a public checkout's IP check still works without the guard. The site-code detector
# is EXTERNALIZED (no literal prefix in source) — empty (never-match) without a token source.
_NEVER = re.compile(r"(?!x)x")
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
SITE_CODE_RE = _GUARD.SITE_CODE_RE if _GUARD else _NEVER  # type: ignore[attr-defined]
_IPV4 = _GUARD._IPV4 if _GUARD else re.compile(rf"(?<![\d.])(?:{_OCTET}\.){{3}}{_OCTET}(?![\d.])")  # type: ignore[attr-defined]
_ALLOWED_IP = (
    _GUARD._ALLOWED_IP  # type: ignore[attr-defined]
    if _GUARD
    else re.compile(
        r"^(?:"
        r"0\.|127\.|10\.|192\.168\.|169\.254\.|255\.|"
        r"172\.(?:1[6-9]|2\d|3[01])\.|"
        r"192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|"
        r"22[4-9]\.|23\d\."
        r")"
    )
)


def scan_text(text: str, *, include_estate: bool = False) -> list[str]:
    """Forbidden-token **reasons** in ``text`` (no matched text) — vendored twin of
    ``scan_forbidden.scan_text``. The site code is checked field-anchored by :func:`leak_check`, not
    here (see the engine docstring)."""
    reasons: list[str] = []
    for pat, reason in FORBIDDEN:
        if pat.search(text):
            reasons.append(reason)
    for m in _IPV4.finditer(text):
        if not _ALLOWED_IP.match(m.group(0)):
            reasons.append("routable IP address")
            break
    if include_estate:
        lowered = text.lower()
        reasons.extend(f"estate token ({token})" for token in ESTATE_TOKENS if token in lowered)
    return reasons


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
    """The full :class:`LeakReport` for ``text`` using the tee's vendored token authority.

    Behaviourally parallel to the engine's :func:`messagefoundry.anon.leak.leak_report`: the token
    hits come from the tee's local :func:`scan_text` (and the field-anchored site-code check) rather
    than the engine's ``_scanner()`` delegate, but the structural walk, coverage report, and
    token-floor signal are the byte-identical shared logic above. Structural detection engages **only
    when ``rules`` is supplied**; a bare-string call is the legacy token-only behaviour.
    """
    token_hits = scan_text(text, include_estate=True)
    if message_has_site_code(text):
        token_hits.append("site-code pattern")
    if rules is None:
        unmapped: tuple[str, ...] = ()
        structural: list[str] = []
    else:
        mapped_paths = {r.path for r in rules}
        unmapped = tuple(sorted({addr for addr, _ in unmapped_field_values(text, mapped_paths)}))
        structural = structural_phi_hits(text, mapped_paths)
    token_tables_live: bool
    token_floor_reason: str | None
    if _GUARD is not None:
        token_tables_live = bool(_GUARD.TOKENS_PRESENT)  # type: ignore[attr-defined]
        token_floor_reason = _GUARD.token_floor_failure()  # type: ignore[attr-defined]
    else:
        token_tables_live = False
        # nosec B105: a human-readable diagnostic string, not a credential — bandit's
        # hardcoded-password heuristic fires only because the name contains "token".
        token_floor_reason = "no publish guard reachable — refusing to run structural-only"  # nosec B105
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
