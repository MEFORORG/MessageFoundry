# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Anonymizer (de-identification) for test datasets — engine side (ADR 0030, BACKLOG #36).

Turns a real, messy HL7 v2 message into a **structurally-faithful, de-identified** copy to commit,
share, and replay as a fixture — the first built slice of the de-identification capability CLAUDE.md
§9 / PHI.md §9 call planned-not-built. Consumed by the standalone **tee** relay and the PySide6
**test harness**; a byte-identical ``tee/anon/`` vendors the shared logic for the dependency-free tee.

Two-layer rule model (ADR 0030 §2): field **selection** is data (:func:`load_rules` over an optional
``anon.toml``); surrogate **production** is code (:mod:`.surrogates`). Surrogates are deterministic
and keyed by a **secret, per-dataset salt** (:class:`.keying.Keyer`) so the same real value maps to
the same surrogate within a dataset and is re-identification-resistant across datasets (ADR 0030 §4).

Public surface:

* :func:`anonymize` — de-identify one HL7 message (raises nothing PHI-bearing).
* :func:`anonymize_checked` — :func:`anonymize` + a **fail-closed** :func:`leak_report`; raises
  :class:`LeakError` (token categories + PHI shapes/addresses only, never a value) if any known
  partner/site token survives, a structural PHI shape sits in a field no rule mapped, or a line
  has a malformed segment id. By default it does **not** refuse a name, an undashed number or a
  date in an unmapped field: those pass, and only the coverage report records the field. The
  opt-in ``require_full_coverage`` refuses a field no rule or ``keep`` decided. Read the report
  before you share a dataset (``docs/PHI.md`` section 9 states the scope).
* :func:`leak_check` / :func:`leak_report` — token hits + structural PHI-shape detection over the
  unmapped fields + the unmapped-field coverage report (ADR 0030 §5, BACKLOG #331).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

from .hl7 import anonymize_message
from .keying import Keyer
from .leak import LeakCheckUnavailable, LeakReport, coverage_clause, leak_check, leak_report
from .rules import DEFAULT_RULES, AnonError, FieldRule, RuleError, SurrogateKind, load_rules

__all__ = [
    "DEFAULT_RULES",
    "AnonError",
    "FieldRule",
    "Keyer",
    "LeakCheckUnavailable",
    "LeakError",
    "LeakReport",
    "RuleError",
    "SurrogateKind",
    "anonymize",
    "anonymize_checked",
    "leak_check",
    "leak_report",
    "load_rules",
]


class LeakError(RuntimeError):
    """An anonymized dataset failed the leak-check — a forbidden token or PHI shape survived, or
    ``require_full_coverage`` found a field nobody decided. Written nowhere, fail closed (§5).

    Carries the token *categories* only (e.g. ``"partner/site token"``), never the offending value,
    so raising/logging it cannot itself leak PHI.
    """


def anonymize(
    raw: str,
    *,
    salt: str,
    overlay: Path | None = None,
    rules: tuple[FieldRule, ...] | None = None,
    blanked: list[str] | None = None,
) -> str:
    """De-identify one HL7 v2 message with the secret ``salt`` and the effective rule set.

    ``rules`` overrides the rule set outright; otherwise :func:`load_rules` is used with the optional
    ``anon.toml`` ``overlay`` path. HL7 v2 only for now — the payload-agnostic seam (ADR 0004 / 0030
    §7) is left for a real X12/FHIR feed; do not feed a non-HL7 body here.

    ``blanked``, when given, collects the address of every field the ``date`` kind scrubbed to empty
    because its value was not a valid timestamp. :func:`anonymize_checked` puts those addresses in
    the report for you; a caller of this function has no other record of them.
    """
    keyer = Keyer(salt)
    if rules is None:
        rules = load_rules(overlay)
    # A KEEP rule is a decision to leave the field alone, so it rewrites nothing.
    rewrites = tuple(r for r in rules if r.kind != SurrogateKind.KEEP)
    return anonymize_message(raw, keyer, rewrites, blanked)


def anonymize_checked(
    raw: str,
    *,
    salt: str,
    overlay: Path | None = None,
    rules: tuple[FieldRule, ...] | None = None,
    require_live_denylist: bool = False,
    require_full_coverage: bool = False,
    on_report: Callable[[LeakReport], None] | None = None,
) -> str:
    """:func:`anonymize`, then a fail-closed :func:`leak_report`; raise :class:`LeakError` on any hit.

    Use this whenever the output may be persisted/shared — a silently-missed token is worse than no
    anonymization (ADR 0030 §5). The verification is now two-layered (BACKLOG #331): the known-token
    denylist **and** high-precision structural PHI-shape detectors over the fields no rule matched,
    scoped by the same ``rules`` the anonymizer applied. The raised error names token *categories* and
    field *shapes/addresses* only, never a value, and carries a coverage clause (the count + addresses
    of the unmapped fields, whether the denylist tables were live) so a refusal is legible.

    A clean return is NOT proof the output is PHI-free. The structural detectors find only a dashed
    SSN, a punctuated NANP phone, an ``MR``/``MRN``-typed CX and a malformed segment line; a name, an
    undashed number or a date in an unmapped field passes (BACKLOG #1710). The coverage report is the
    record of those fields, so pass ``on_report`` and surface it on the clean path too.

    ``require_live_denylist`` makes a non-live token source (``token_floor_reason`` set) a refusal
    cause in its own right — the strict lever for a deployment that must not de-identify with the
    customer denylist unloaded. It defaults **off**: the structural detectors are the live backstop,
    and CI/OSS/fork runs legitimately have no token source. ``on_report`` receives the full
    :class:`LeakReport` on both the clean and the refusing path (default: no emission).

    ``require_full_coverage`` (default off) refuses any present field that no rule scrubs and no
    ``anon.toml`` ``keep`` names, other than :data:`.leak.ALWAYS_DECIDED` (set ids, PID-8, PV1-2).
    It asks whether every field was DECIDED, not whether its value is safe: a kept field passes
    it and is still scanned for PHI shapes. The MSH header is outside its reach (BACKLOG #1710).

    The report's ``blanked_fields`` names each field the ``date`` kind scrubbed to empty because the
    value was not a valid timestamp. It is a record, not a refusal cause (BACKLOG #2330).
    """
    effective = rules if rules is not None else load_rules(overlay)
    blanked: list[str] = []
    output = anonymize(raw, salt=salt, rules=effective, blanked=blanked)
    report = replace(
        leak_report(output, rules=effective), blanked_fields=tuple(sorted(set(blanked)))
    )
    if on_report is not None:
        on_report(report)
    causes = list(report.hits)
    if require_live_denylist and report.token_floor_reason is not None:
        causes.append(f"denylist not live: {report.token_floor_reason}")
    if require_full_coverage and report.undecided_fields:
        causes.append(
            f"{len(report.undecided_fields)} field(s) with no rule and no keep: "
            + ", ".join(report.undecided_fields)
        )
    if causes:
        raise LeakError(
            "anonymized output failed the leak-check: "
            + "; ".join(sorted(set(causes)))
            + " — refusing to emit (fail closed). Extend the rule map for a missed field, add a keep for"
            + " a field you reviewed, or repair a line with a malformed segment id."
            + coverage_clause(report)
        )
    return output
