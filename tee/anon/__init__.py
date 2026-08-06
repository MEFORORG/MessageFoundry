# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Anonymizer for the standalone tee (ADR 0030, BACKLOG #36) — vendored twin of ``messagefoundry.anon``.

Turns captured real HL7 v2 into a structurally-faithful, PHI-free dataset, with **no**
``messagefoundry`` import (the tee sits on the Epic/Corepoint boundary and stays standalone — it
vendors the shared logic, mirroring ``tee/hl7_fields.py``/``tee/mllp.py``). The shared files
(``keying``/``rules``/``surrogates`` + the vendored ``_hl7data``) are held byte-identical to the
engine's by the parity test; the adapter/leak seams are behaviourally parallel (golden-corpus test).

Public surface (same shape as the engine's):

* :func:`anonymize` — de-identify one HL7 message.
* :func:`anonymize_checked` — :func:`anonymize` + a fail-closed :func:`leak_report`; raises
  :class:`LeakError` (token categories + PHI shapes/addresses only) on any surviving token or a
  structural PHI shape in a field no rule mapped.
* :func:`leak_check` / :func:`leak_report` — token hits + structural PHI-shape detection over the
  unmapped fields + the unmapped-field coverage report (vendored twin of the engine's; BACKLOG #331).
"""

from __future__ import annotations

from collections.abc import Callable
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
    """An anonymized dataset still carried a forbidden token — written nowhere, fail closed (§5).

    Carries token *categories* only, never the offending value, so it is safe to raise/log.
    """


def anonymize(
    raw: str,
    *,
    salt: str,
    overlay: Path | None = None,
    rules: tuple[FieldRule, ...] | None = None,
) -> str:
    """De-identify one HL7 v2 message with the secret ``salt`` and the effective rule set."""
    keyer = Keyer(salt)
    if rules is None:
        rules = load_rules(overlay)
    return anonymize_message(raw, keyer, rules)


def anonymize_checked(
    raw: str,
    *,
    salt: str,
    overlay: Path | None = None,
    rules: tuple[FieldRule, ...] | None = None,
    require_live_denylist: bool = False,
    on_report: Callable[[LeakReport], None] | None = None,
) -> str:
    """:func:`anonymize`, then a fail-closed :func:`leak_report`; raise :class:`LeakError` on any hit.

    Two-layered like the engine's (BACKLOG #331): the known-token denylist plus high-precision
    structural PHI-shape detectors over the fields no rule matched. ``require_live_denylist`` (default
    off) makes a non-live token source a refusal cause; ``on_report`` receives the :class:`LeakReport`
    on both paths. The error names token categories and field shapes/addresses only, never a value.
    """
    effective = rules if rules is not None else load_rules(overlay)
    output = anonymize(raw, salt=salt, rules=effective)
    report = leak_report(output, rules=effective)
    if on_report is not None:
        on_report(report)
    causes = list(report.hits)
    if require_live_denylist and report.token_floor_reason is not None:
        causes.append(f"denylist not live: {report.token_floor_reason}")
    if causes:
        raise LeakError(
            "anonymized output still carries forbidden token(s): "
            + "; ".join(sorted(set(causes)))
            + " — refusing to emit (fail closed). Extend the rule map for the missed field(s)."
            + coverage_clause(report)
        )
    return output
