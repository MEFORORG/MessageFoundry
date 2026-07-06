# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""AI-assistance **policy model** — the authoritative two-axis policy and its clamping algorithm.

A central operator governs how much AI coding assistance is permitted across a spectrum from
**OFF** to **PHI-safe**, expressed as two independent axes bounded by a posture ceiling:

* **mode** (:class:`AiMode`) — *whether and how* assistance runs: ``off`` (none), ``byo``
  (the user's own provider; this extension version's only working path), or the engine-brokered
  ``managed_claude`` / ``managed_claude_baa`` (P1/P2 — not built here, but a policy may already
  declare them so the IDE refuses rather than silently downgrading).
* **data_scope** (:class:`AiDataScope`) — *how sensitive* the context attached to a request may be,
  ordered least→most sensitive: ``code_only`` < ``synthetic`` < ``deidentified`` < ``phi``.

The instance's **production** posture flag imposes a ceiling on ``data_scope`` so the same config
behaves conservatively on a non-production instance and only reaches ``phi`` on a production instance
under a BAA mode. ``mode`` itself is never clamped — a central ``off`` is honored everywhere. Posture
is **decoupled from the environment *name*** (ADR 0017): an instance is ``production`` (and/or
PHI-carrying, see :class:`DataClass`) regardless of whether it is literally named ``prod`` — so an
org can name instances ``poc``/``test``/… while choosing posture explicitly.

This module is **pure** (no I/O) and imports nothing from :mod:`messagefoundry.config.settings`
(the dependency is one-way: settings imports these enums, not the reverse, to avoid a cycle). It is
consumed by the ``GET /ai/policy`` API endpoint and the ``messagefoundry ai-policy`` CLI, which both
serialize :class:`EffectivePolicy` to the shared snake_case wire shape.

Note: the ``deidentified`` scope depends on a de-identification framework that **does not exist in
this repo** (roadmap only); :func:`resolve_effective_policy` therefore always clamps it down rather
than pretending it is reachable.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class AiMode(str, Enum):
    """Whether and how AI assistance runs. The value is the wire/storage string."""

    OFF = "off"  # no assistance at all
    BYO = "byo"  # bring-your-own provider (the only working path in this MVP)
    MANAGED_CLAUDE = "managed_claude"  # engine-brokered Claude (P1; not built here)
    MANAGED_CLAUDE_BAA = "managed_claude_baa"  # brokered Claude under a BAA (P2; unlocks phi scope)


class AiDataScope(str, Enum):
    """How sensitive the context attached to an AI request may be. The value is the wire string."""

    CODE_ONLY = "code_only"  # graph names + editor code only (PHI-safe by construction)
    SYNTHETIC = "synthetic"  # plus synthetic/sample HL7
    DEIDENTIFIED = "deidentified"  # de-identified PHI (needs the unbuilt de-id framework)
    PHI = "phi"  # real message bodies (only over a BAA + zero-retention provider)


class DataClass(str, Enum):
    """Whether an instance handles real PHI, **independent of its (free-form) environment name**.

    Drives the at-rest-encryption + open-egress startup advisories (a synthetic instance stays quiet;
    a ``phi`` instance is warned). The AI data-scope ceiling keys off the separate ``production`` flag,
    not this. Decoupling the data class from the environment name (ADR 0017) lets an org name instances
    freely (``poc``/``test``/…) while choosing posture explicitly. The value is the wire string."""

    SYNTHETIC = "synthetic"  # synthetic/sample data only — relaxed at-rest/egress posture
    PHI = "phi"  # carries real PHI — encryption + egress advisories apply


#: Scope ordering, least→most sensitive. Used to take the *lower* of (requested, ceiling).
_SCOPE_ORDER: dict[AiDataScope, int] = {
    AiDataScope.CODE_ONLY: 0,
    AiDataScope.SYNTHETIC: 1,
    AiDataScope.DEIDENTIFIED: 2,
    AiDataScope.PHI: 3,
}


@dataclass(frozen=True)
class EffectivePolicy:
    """The clamped, enforceable policy returned by :func:`resolve_effective_policy`.

    ``reason`` is a human-readable, ``"; "``-joined note of every clamp applied (``None`` when the
    requested policy passed through unchanged) — surfaced in the API/CLI so an operator can see *why*
    the effective scope differs from what was configured. The environment *name* and the posture
    (``data_class``/``production``) are carried by the caller's wire model, not here.
    """

    mode: AiMode
    data_scope: AiDataScope
    reason: str | None


def resolve_effective_policy(
    *, mode: AiMode, data_scope: AiDataScope, production: bool
) -> EffectivePolicy:
    """Clamp a requested (mode, data_scope) to the enforceable effective policy for this instance.

    The algorithm (in order): apply the production-posture data-scope ceiling; defensively block
    ``phi`` unless the mode is BAA-managed; block ``deidentified`` (the de-id framework is unbuilt);
    and normalize scope to ``code_only`` when the mode is ``off``. ``mode`` is never clamped — a
    central ``off``/managed choice is honored regardless of posture. ``production`` is the instance's
    posture flag (decoupled from the environment *name*, ADR 0017), not whether it is literally named
    ``prod``.
    """
    reasons: list[str] = []

    # 1. Posture data-scope ceiling. A non-production instance never exceeds synthetic; a production
    #    instance reaches phi only under a BAA-managed mode, otherwise it floors at code_only.
    if production:
        ceiling = AiDataScope.PHI if mode is AiMode.MANAGED_CLAUDE_BAA else AiDataScope.CODE_ONLY
    else:
        ceiling = AiDataScope.SYNTHETIC

    eff = data_scope
    if _SCOPE_ORDER[ceiling] < _SCOPE_ORDER[eff]:
        eff = ceiling
        tier = "production" if production else "non-production"
        reasons.append(f"data scope capped to {eff.value} by a {tier} instance")

    # 2. phi hard rule (defensive): phi requires a BAA-managed mode. The ceiling already enforces
    #    this on a production instance; this guards any path that reached phi outside it.
    if eff is AiDataScope.PHI and mode is not AiMode.MANAGED_CLAUDE_BAA:
        eff = AiDataScope.CODE_ONLY
        reasons.append("phi scope requires managed_claude_baa mode; fell back to code_only")

    # 3. deidentified hard rule: the de-id framework is roadmap only, so this scope is never live.
    if eff is AiDataScope.DEIDENTIFIED:
        eff = AiDataScope.CODE_ONLY
        reasons.append(
            "deidentified scope requires the (unbuilt) de-id framework; fell back to code_only"
        )

    # 4. off normalization: when AI is off the scope is irrelevant — pin it to the safe floor.
    if mode is AiMode.OFF:
        eff = AiDataScope.CODE_ONLY

    return EffectivePolicy(
        mode=mode,
        data_scope=eff,
        reason="; ".join(reasons) if reasons else None,
    )
