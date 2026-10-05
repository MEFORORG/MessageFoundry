# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Anonymizer for the standalone tee (ADR 0030, BACKLOG #36) — vendored twin of ``messagefoundry.anon``.

Turns captured real HL7 v2 into a structurally-faithful, de-identified dataset, with **no**
``messagefoundry`` import (the tee sits on the Epic/Corepoint boundary and stays standalone — it
vendors the shared logic, mirroring ``tee/hl7_fields.py``/``tee/mllp.py``). The shared files
(``keying``/``rules``/``surrogates`` + the vendored ``_hl7data``) are held byte-identical to the
engine's by the parity test; the adapter/leak seams are behaviourally parallel (golden-corpus test).

Public surface (same shape as the engine's):

* :func:`anonymize` — de-identify one HL7 message.
* :func:`anonymize_checked` — :func:`anonymize` + a fail-closed :func:`leak_report`; raises
  :class:`LeakError` (token categories + PHI shapes/addresses only) on any surviving token, a
  structural PHI shape in a field no rule mapped, or a line with a malformed segment id. A name,
  an undashed number or a date in an unmapped field passes; only the coverage report records it.
* :func:`leak_check` / :func:`leak_report` — token hits + structural PHI-shape detection over the
  unmapped fields + the unmapped-field coverage report (vendored twin of the engine's; BACKLOG #331).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

from .hl7 import anonymize_message
from .keying import Keyer
from .leak import LeakReport, coverage_clause, leak_check, leak_report
from .rules import DEFAULT_RULES, AnonError, FieldRule, RuleError, SurrogateKind, load_rules

__all__ = [
    "DEFAULT_RULES",
    "AnonError",
    "FieldRule",
    "Keyer",
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

    Carries token *categories* only, never the offending value, so it is safe to raise/log.
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

    ``blanked``, when given, collects the address of every field the ``date`` kind scrubbed to empty
    because its value was not a valid timestamp.
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

    Two-layered like the engine's (BACKLOG #331): the known-token denylist plus high-precision
    structural PHI-shape detectors over the fields no rule matched. ``require_live_denylist`` (default
    off) makes a non-live token source a refusal cause; ``require_full_coverage`` (default off)
    refuses any present field no rule scrubs and no ``keep`` names, other than set ids, PID-8 and
    PV1-2, and a kept field is still scanned; ``on_report`` receives the :class:`LeakReport`
    on both paths. The error names token categories and field shapes/addresses only, never a value.
    A clean return is not proof of PHI-free output: a name, an undashed number or a date in an
    unmapped field passes, so surface the ``on_report`` coverage on the clean path (BACKLOG #1710).
    The report's ``blanked_fields`` names each field the ``date`` kind scrubbed to empty because the
    value was not a valid timestamp; it is a record, not a refusal cause (BACKLOG #2330).
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
