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
* :func:`anonymize_checked` — :func:`anonymize` + a fail-closed :func:`leak_check`; raises
  :class:`LeakError` (token categories only) on any surviving token.
* :func:`leak_check` — forbidden-token hits via the vendored token authority.
"""

from __future__ import annotations

from pathlib import Path

from .hl7 import anonymize_message
from .keying import Keyer
from .leak import leak_check
from .rules import AnonError, DEFAULT_RULES, FieldRule, RuleError, SurrogateKind, load_rules

__all__ = [
    "DEFAULT_RULES",
    "AnonError",
    "FieldRule",
    "Keyer",
    "LeakError",
    "RuleError",
    "SurrogateKind",
    "anonymize",
    "anonymize_checked",
    "leak_check",
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
) -> str:
    """:func:`anonymize`, then a fail-closed :func:`leak_check`; raise :class:`LeakError` on any hit."""
    output = anonymize(raw, salt=salt, overlay=overlay, rules=rules)
    hits = leak_check(output)
    if hits:
        raise LeakError(
            "anonymized output still carries forbidden token(s): "
            + "; ".join(sorted(set(hits)))
            + " — refusing to emit (fail closed). Extend the rule map for the missed field(s)."
        )
    return output
