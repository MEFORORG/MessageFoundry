"""AI-assistance **policy model** — the authoritative two-axis policy and its clamping algorithm.

A central operator governs how much AI coding assistance is permitted across a spectrum from
**OFF** to **PHI-safe**, expressed as two independent axes bounded by an environment ceiling:

* **mode** (:class:`AiMode`) — *whether and how* assistance runs: ``off`` (none), ``byo``
  (the user's own provider; this extension version's only working path), or the engine-brokered
  ``managed_claude`` / ``managed_claude_baa`` (P1/P2 — not built here, but a policy may already
  declare them so the IDE refuses rather than silently downgrading).
* **data_scope** (:class:`AiDataScope`) — *how sensitive* the context attached to a request may be,
  ordered least→most sensitive: ``code_only`` < ``synthetic`` < ``deidentified`` < ``phi``.

The **environment** (:class:`AiEnvironment`) imposes a ceiling on ``data_scope`` so the same
config behaves conservatively in dev/staging and only reaches ``phi`` in ``prod`` under a BAA mode.
``mode`` itself is never clamped by environment — a central ``off`` is honored everywhere.

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


class AiEnvironment(str, Enum):
    """The deployment environment, which imposes a data-scope ceiling. The value is the wire string."""

    DEV = "dev"
    STAGING = "staging"
    PROD = "prod"


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
    the effective scope differs from what was configured.
    """

    mode: AiMode
    data_scope: AiDataScope
    environment: AiEnvironment
    reason: str | None


def resolve_effective_policy(
    *, mode: AiMode, data_scope: AiDataScope, environment: AiEnvironment
) -> EffectivePolicy:
    """Clamp a requested (mode, data_scope, environment) to the enforceable effective policy.

    The algorithm (in order): apply the environment's data-scope ceiling; defensively block ``phi``
    unless the mode is BAA-managed; block ``deidentified`` (the de-id framework is unbuilt); and
    normalize scope to ``code_only`` when the mode is ``off``. ``mode`` is never clamped — a central
    ``off``/managed choice is honored regardless of environment.
    """
    reasons: list[str] = []

    # 1. Environment data-scope ceiling. dev/staging never exceed synthetic; prod reaches phi only
    #    under a BAA-managed mode, otherwise it floors at code_only.
    if environment is AiEnvironment.PROD:
        ceiling = AiDataScope.PHI if mode is AiMode.MANAGED_CLAUDE_BAA else AiDataScope.CODE_ONLY
    else:  # dev, staging
        ceiling = AiDataScope.SYNTHETIC

    eff = data_scope
    if _SCOPE_ORDER[ceiling] < _SCOPE_ORDER[eff]:
        eff = ceiling
        reasons.append(f"data scope capped to {eff.value} by environment={environment.value}")

    # 2. phi hard rule (defensive): phi requires a BAA-managed mode. The ceiling already enforces
    #    this in prod; this guards any path that reached phi outside it.
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
        environment=environment,
        reason="; ".join(reasons) if reasons else None,
    )
