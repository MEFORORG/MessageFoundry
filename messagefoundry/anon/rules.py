# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The de-identification **rule model** — which HL7 field gets which *kind* of surrogate (ADR 0030 §2).

A de-id rule has two halves and the project identity dictates which is which:

* **WHICH** field is scrubbed and **WHAT KIND** of surrogate it gets is **data** — the declarative
  :data:`DEFAULT_RULES` map of ``FieldRule(path, kind)``, optionally overlaid by an ``anon.toml`` —
  the same sanctioned config category as ``connections.toml`` (ADR 0007). A deployment customising
  *which* PHI fields to scrub edits data, not code.
* **HOW** a surrogate is produced is **code** — the pure functions in
  :mod:`messagefoundry.anon.surrogates`, keyed by :class:`SurrogateKind`.

The data layer is deliberately incapable of expressing a *transform*: a rule may only map a
whole-**field** path to an existing :class:`SurrogateKind` (or ``keep``/``drop``). There is no
expression language, no conditionals, no field arithmetic — the moment a rule needs to *do*
something new, that is a code change in ``surrogates.py``. :func:`load_rules` **enforces** this at
load time (it rejects any overlay key that is not a ``path -> kind``/``keep``/``drop``), so the
config can never drift into declarative *logic* authoring (CLAUDE.md §12). This shapes test data;
it is tooling-side only and never enters a Router/Handler or ``pipeline/``.

Pure stdlib — byte-identical with ``tee/anon/rules.py`` (parity test); no ``messagefoundry`` import.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

#: A whole-FIELD HL7 address: a 3-char segment id then ``-`` then a 1-based field number
#: (``PID-5``, ``MRG-1``). Component paths (``PID-5.1``) are rejected — surrogates compose a whole
#: field's value (ADR 0030 §3), so rules address whole fields only.
_FIELD_PATH_RE = re.compile(r"^[A-Z][A-Z0-9]{2}-\d+$")


class SurrogateKind(StrEnum):
    """The kind of surrogate a field gets. ``KEEP``/``DROP`` are overlay actions, not surrogates."""

    NAME = "name"  # XPN person name (PID-5/6/9, NK1-2, GT1-3, IN1-16, MRG-4/7)
    ADDRESS = "address"  # XAD address (PID-11, NK1-4, GT1-5, IN1-19)
    MRN = "mrn"  # CX medical-record / patient identifier (PID-3, MRG-1/3)
    SSN = "ssn"  # social-security / national id (PID-19, GT1-12, IN2-2)
    PHONE = "phone"  # XTN phone/contact (PID-13/14, NK1-5/6/7, GT1-6/7)
    DOB = "dob"  # DT/TS date of birth (PID-7)
    DATE = "date"  # DTM/TS event date: keep the year, fill the rest (EVN-2, PV1-44, OBR-7, ...)
    ID = "id"  # a generic identifier (PID-4/18/20, IN1-36/49, PV1-19)
    PROVIDER = "provider"  # XCN clinician (PV1-7/8/9/17, PD1-4, ORC-12, OBR-16/32, OBX-16)
    FREETEXT = "freetext"  # narrative that may embed identifiers — blunt full-redact (OBX-5, NTE-3)
    KEEP = "keep"  # leave the field intact (overlay: cancel a default scrub)
    DROP = "drop"  # blank the field entirely (overlay)


class RuleError(ValueError):
    """A rule the data layer refuses: a malformed ``anon.toml`` overlay, one that tries to express
    something the data layer deliberately cannot (ADR 0030 §2 — selection only, never logic), or
    a :class:`FieldRule` built in code with an unknown kind."""


def _coerce_kind(path: str, raw: object) -> SurrogateKind:
    if not isinstance(raw, str):
        raise RuleError(f"rule for {path!r} must name a surrogate kind as a string, got {raw!r}")
    try:
        return SurrogateKind(raw)
    except ValueError:
        allowed = ", ".join(k.value for k in SurrogateKind)
        raise RuleError(
            f"rule for {path!r} names unknown surrogate kind {raw!r}; allowed: {allowed}. "
            "A new kind is a code change in surrogates.py, never an overlay value."
        ) from None


@dataclass(frozen=True)
class FieldRule:
    """One rule: scrub the whole field at ``path`` with surrogate ``kind``.

    ``kind`` is normalized to THIS package's :class:`SurrogateKind` on construction, so a plain
    ``"drop"`` string, or the other package's member, becomes the member here. An unknown kind
    raises :class:`RuleError` at construction, not at the first message. A rule built by the other
    package still carries that package's member, which is why the adapters and the leak-check
    compare a kind by value rather than by identity.
    """

    path: str
    kind: SurrogateKind

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", _coerce_kind(self.path, self.kind))


# The recommended default scrub map (ADR 0030 §3). Anything NOT listed is left intact — so the
# routing/coded fields (MSH-7/9/10/12, NK1-3 relationship, IN1-2/3/4 plan codes, DG1/AL1/PR1,
# OBR-4 service) survive untouched and correlation + parity-diff (#14) still work.
#
# The DATE and location rules map these Safe Harbor date and location fields, and that is NOT Safe
# Harbor de-identification: MSH-7 keeps the full message time, the order and accession numbers
# (ORC-2/3, OBR-2/3) are left unmapped, and so are other date fields (BACKLOG #2248).
#
# MRG fields are scrubbed with the SAME kinds as their PID counterparts (MRG-1 with PID-3, MRG-4
# with PID-5) and keyed on the same value, so an A40 merge's old-to-new linkage is preserved across
# the surrogate mapping.
DEFAULT_RULES: tuple[FieldRule, ...] = (
    # PID — patient identity
    FieldRule("PID-3", SurrogateKind.MRN),
    FieldRule("PID-4", SurrogateKind.ID),
    FieldRule("PID-5", SurrogateKind.NAME),
    FieldRule("PID-6", SurrogateKind.NAME),
    FieldRule("PID-7", SurrogateKind.DOB),
    FieldRule("PID-9", SurrogateKind.NAME),
    FieldRule("PID-11", SurrogateKind.ADDRESS),
    # PID-12 and PV1-3 take the blunt FREETEXT redact until a shape-keeping location kind exists:
    # a CWE county can name the county, and a PL location carries free text in PL.9.
    FieldRule("PID-12", SurrogateKind.FREETEXT),
    FieldRule("PID-13", SurrogateKind.PHONE),
    FieldRule("PID-14", SurrogateKind.PHONE),
    FieldRule("PID-18", SurrogateKind.ID),
    FieldRule("PID-19", SurrogateKind.SSN),
    FieldRule("PID-20", SurrogateKind.ID),
    FieldRule("PID-29", SurrogateKind.DATE),  # death date/time
    # MRG — merge (A40); keep linkage to the PID kinds above
    FieldRule("MRG-1", SurrogateKind.MRN),
    FieldRule("MRG-3", SurrogateKind.MRN),
    FieldRule("MRG-4", SurrogateKind.NAME),
    FieldRule("MRG-7", SurrogateKind.NAME),
    # NK1 — next of kin / contacts (NK1-3 relationship code is KEPT by omission)
    FieldRule("NK1-2", SurrogateKind.NAME),
    FieldRule("NK1-4", SurrogateKind.ADDRESS),
    FieldRule("NK1-5", SurrogateKind.PHONE),
    FieldRule("NK1-6", SurrogateKind.PHONE),
    FieldRule("NK1-7", SurrogateKind.PHONE),
    # GT1 — guarantor
    FieldRule("GT1-3", SurrogateKind.NAME),
    FieldRule("GT1-5", SurrogateKind.ADDRESS),
    FieldRule("GT1-6", SurrogateKind.PHONE),
    FieldRule("GT1-7", SurrogateKind.PHONE),
    FieldRule("GT1-12", SurrogateKind.SSN),
    # IN1/IN2 — insurance (plan/company codes IN1-2/3/4 are KEPT by omission)
    FieldRule("IN1-16", SurrogateKind.NAME),
    FieldRule("IN1-19", SurrogateKind.ADDRESS),
    FieldRule("IN1-36", SurrogateKind.ID),
    FieldRule("IN1-49", SurrogateKind.ID),
    FieldRule("IN2-2", SurrogateKind.SSN),
    FieldRule("IN2-3", SurrogateKind.FREETEXT),
    # EVN — event dates (the recorded and the occurred time)
    FieldRule("EVN-2", SurrogateKind.DATE),
    FieldRule("EVN-6", SurrogateKind.DATE),
    # PV1/PD1 — visit + providers
    FieldRule("PV1-3", SurrogateKind.FREETEXT),  # assigned location, see PID-12
    FieldRule("PV1-7", SurrogateKind.PROVIDER),
    FieldRule("PV1-8", SurrogateKind.PROVIDER),
    FieldRule("PV1-9", SurrogateKind.PROVIDER),
    FieldRule("PV1-17", SurrogateKind.PROVIDER),
    FieldRule("PV1-19", SurrogateKind.ID),
    FieldRule("PV1-44", SurrogateKind.DATE),  # admit date/time
    FieldRule("PV1-45", SurrogateKind.DATE),  # discharge date/time
    FieldRule("PD1-4", SurrogateKind.PROVIDER),
    # ORC/OBR/OBX — orders, results, observations
    FieldRule("ORC-9", SurrogateKind.DATE),  # transaction date/time
    FieldRule("ORC-12", SurrogateKind.PROVIDER),
    FieldRule("OBR-7", SurrogateKind.DATE),  # observation date/time
    FieldRule("OBR-16", SurrogateKind.PROVIDER),
    FieldRule("OBR-32", SurrogateKind.PROVIDER),
    FieldRule("OBX-5", SurrogateKind.FREETEXT),
    FieldRule("OBX-14", SurrogateKind.DATE),  # observation date/time
    FieldRule("OBX-16", SurrogateKind.PROVIDER),
    # NTE — notes / comments
    FieldRule("NTE-3", SurrogateKind.FREETEXT),
)


class AnonError(ValueError):
    """The anonymizer cannot safely de-identify a message (no parseable MSH / encoding chars, or a
    malformed structure) — a **fail-closed** refusal (ADR 0030 §3: *withhold + error, never emit
    un-anonymized*). Carries no message body, so it is safe to raise/log. Subclasses ``ValueError``
    so existing fail-closed call-site catches treat it as a drop-and-count."""


def _validate_path(path: str) -> str:
    if not _FIELD_PATH_RE.match(path):
        raise RuleError(
            f"rule path {path!r} is not a whole-field HL7 address like 'PID-5' "
            "(component paths and free text are rejected — selection is field-level only)"
        )
    return path


def load_rules(overlay: Path | None = None) -> tuple[FieldRule, ...]:
    """The effective rule set: :data:`DEFAULT_RULES` optionally overlaid by an ``anon.toml``.

    The overlay may ONLY map fields to existing kinds — its schema is enforced so the data layer
    can never express a transform (ADR 0030 §2). Accepted shape::

        [hl7.fields]      # add or retarget a field -> kind
        "ZPD-2" = "mrn"
        "PID-5" = "name"

        [hl7]
        keep = ["PID-13"]  # cancel a default scrub, or record a field as reviewed and left intact
        drop = ["PID-40"]  # blank the field entirely

    Any other table/key, a component path, or an unknown kind raises :class:`RuleError`.

    A ``keep`` comes back as a :attr:`SurrogateKind.KEEP` rule. The anonymizer rewrites nothing for
    it; the leak-check counts the field as DECIDED for ``require_full_coverage`` and still scans
    it for PHI shapes (BACKLOG #1710).
    """
    effective: dict[str, SurrogateKind] = {r.path: r.kind for r in DEFAULT_RULES}
    if overlay is None:
        return DEFAULT_RULES

    try:
        data = tomllib.loads(overlay.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise RuleError(f"cannot read anon overlay {overlay}: {exc}") from exc

    unknown_top = set(data) - {"hl7"}
    if unknown_top:
        raise RuleError(
            f"anon overlay has unexpected top-level key(s) {sorted(unknown_top)}; "
            "only an [hl7] section (fields/keep/drop) is allowed"
        )
    hl7 = data.get("hl7", {})
    if not isinstance(hl7, dict):
        raise RuleError("anon overlay [hl7] must be a table")
    unknown_hl7 = set(hl7) - {"fields", "keep", "drop"}
    if unknown_hl7:
        raise RuleError(
            f"anon overlay [hl7] has unexpected key(s) {sorted(unknown_hl7)}; "
            "only 'fields', 'keep', 'drop' are allowed"
        )

    fields = hl7.get("fields", {})
    if not isinstance(fields, dict):
        raise RuleError("anon overlay [hl7.fields] must be a table of path = kind")
    for path, raw_kind in fields.items():
        effective[_validate_path(path)] = _coerce_kind(path, raw_kind)
    for path in _as_path_list(hl7, "keep"):
        effective[_validate_path(path)] = SurrogateKind.KEEP
    for path in _as_path_list(hl7, "drop"):
        effective[_validate_path(path)] = SurrogateKind.DROP

    # A KEEP rule is returned, not dropped: it is the record that someone decided the field.
    return tuple(FieldRule(path, kind) for path, kind in effective.items())


def _as_path_list(hl7: dict[str, object], key: str) -> list[str]:
    value = hl7.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise RuleError(f"anon overlay [hl7].{key} must be a list of field paths")
    return [str(v) for v in value]
