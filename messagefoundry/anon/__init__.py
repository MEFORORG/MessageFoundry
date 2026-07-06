# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Anonymizer (de-identification) for PHI-free test datasets — engine side (ADR 0030, BACKLOG #36).

Turns a real, messy HL7 v2 message into a **structurally-faithful, PHI-free** copy safe to commit,
share, and replay as a fixture — the first built slice of the de-identification capability CLAUDE.md
§9 / PHI.md §9 call planned-not-built. Consumed by the standalone **tee** relay and the PySide6
**test harness**; a byte-identical ``tee/anon/`` vendors the shared logic for the dependency-free tee.

Two-layer rule model (ADR 0030 §2): field **selection** is data (:func:`load_rules` over an optional
``anon.toml``); surrogate **production** is code (:mod:`.surrogates`). Surrogates are deterministic
and keyed by a **secret, per-dataset salt** (:class:`.keying.Keyer`) so the same real value maps to
the same surrogate within a dataset and is re-identification-resistant across datasets (ADR 0030 §4).

Public surface:

* :func:`anonymize` — de-identify one HL7 message (raises nothing PHI-bearing).
* :func:`anonymize_checked` — :func:`anonymize` + a **fail-closed** :func:`leak_check`; raises
  :class:`LeakError` (token categories only, never the value) if any known partner/site token
  survives. This is how you *earn* the right to write a dataset to a shareable location.
* :func:`leak_check` — forbidden-token hits via the publish-guard authority (ADR 0030 §5).
"""

from __future__ import annotations

from pathlib import Path

from .hl7 import anonymize_message
from .keying import Keyer
from .leak import LeakCheckUnavailable, leak_check
from .rules import AnonError, DEFAULT_RULES, FieldRule, RuleError, SurrogateKind, load_rules

__all__ = [
    "DEFAULT_RULES",
    "AnonError",
    "FieldRule",
    "Keyer",
    "LeakCheckUnavailable",
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

    Carries the token *categories* only (e.g. ``"partner/site token"``), never the offending value,
    so raising/logging it cannot itself leak PHI.
    """


def anonymize(
    raw: str,
    *,
    salt: str,
    overlay: Path | None = None,
    rules: tuple[FieldRule, ...] | None = None,
) -> str:
    """De-identify one HL7 v2 message with the secret ``salt`` and the effective rule set.

    ``rules`` overrides the rule set outright; otherwise :func:`load_rules` is used with the optional
    ``anon.toml`` ``overlay`` path. HL7 v2 only for now — the payload-agnostic seam (ADR 0004 / 0030
    §7) is left for a real X12/FHIR feed; do not feed a non-HL7 body here.
    """
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
    """:func:`anonymize`, then a fail-closed :func:`leak_check`; raise :class:`LeakError` on any hit.

    Use this whenever the output may be persisted/shared — a silently-missed token is worse than no
    anonymization (ADR 0030 §5). The raised error names token *categories* only, never the value.
    """
    output = anonymize(raw, salt=salt, overlay=overlay, rules=rules)
    hits = leak_check(output)
    if hits:
        raise LeakError(
            "anonymized output still carries forbidden token(s): "
            + "; ".join(sorted(set(hits)))
            + " — refusing to emit (fail closed). Extend the rule map for the missed field(s)."
        )
    return output
