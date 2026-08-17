// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Organization and contributors
// The pure, vscode-free half of the IDE's AI-policy handling: the resolved policy shape, and the
// authoritative-merge rule that decides what a FRESH engine answer may and may not overwrite.
//
// THIS MODULE MUST KEEP ZERO IMPORTS. It is separated from aiPolicy.ts (which imports `vscode`)
// for one measured reason: `ide/package.json`'s `test:unit` script explicitly `--ignore`s
// `out/test/suite/ai-policy.test.js`, so anything asserted only there runs solely in the
// Windows-only `npm test` leg. A zero-import module is assertable in the node-side runner that
// executes on EVERY ide CI leg — which is where a security invariant belongs. Adding a value
// import of any vscode-touching module kills `ai-policy-model.test.ts` in that runner with
// "Cannot find module 'vscode'".

/** The resolved AI policy, as the IDE uses it (camelCase; see aiPolicy.ts's `fromWire`). */
export interface AiPolicy {
  mode: string;
  dataScope: string;
  environment: string | null;
  // null = RBAC could not be evaluated (no/invalid token under enabled auth, or resolved offline).
  assistPermitted: boolean | null;
  reason: string | null;
}

/**
 * Narrow a permission bit to the EVALUABLE domain. Only the literals `true` and `false` are answers;
 * everything else means "not evaluated", NEVER "permitted".
 *
 * This exists because {@link AiPolicy} is a COMPILE-TIME claim about a network response and
 * `JSON.parse` does not honour it. The engine ships `assist_permitted: bool | None`, but a 200 from
 * anything else on that URL — a proxy, a mistyped target, an engine build predating the field — can
 * omit it, and an absent property reads as `undefined`. Without this narrowing `undefined` slips past
 * the `=== null` guard below (`undefined !== null`), overwrites a cached deny, and — not being `false`
 * either — POISONS the cache so no later answer can restore the deny. That is the fail-OPEN direction,
 * reached by exactly the degraded answer this control exists to survive, so the narrowing is part of
 * the control rather than defensive tidying. Takes `unknown` because at runtime it genuinely is.
 */
export function evaluatedPermission(v: unknown): boolean | null {
  return v === true || v === false ? v : null;
}

/**
 * Merge a FRESH authoritative (engine) policy over the last cached one, retaining an
 * `assistPermitted: false` that the fresh answer could not re-evaluate.
 *
 * The engine computes `assist_permitted` from the ACTING IDENTITY, so it is `null` for any read the
 * engine could not attribute to a user (no bearer, an expired session, auth disabled mid-flight).
 * Without this rule such a read silently overwrites a cached, authoritatively-observed deny — i.e. a
 * degraded answer would UPGRADE assistance that a central policy had switched off (SEC-022 is the
 * control this completes; ADR 0035).
 *
 * Four properties, each of which is a test — change one and a named test goes red:
 *
 *  1. **Asymmetric on purpose — only a DENY is sticky.** A cached `true` is NOT carried over a fresh
 *     `null`, because `null` under BYO is *allowed by design* (docs/AI.md's tokenless-IDE trust note:
 *     BYO sends code-only context to the developer's own provider, so there is no PHI for RBAC to
 *     protect at that stage). Carrying a `true` forward would fabricate a permit from stale state,
 *     which is the fail-OPEN direction.
 *  2. **Only `assistPermitted` is retained.** `mode` / `dataScope` / `environment` / `reason` always
 *     come fresh, because `mode` is identity-INDEPENDENT: a central `off` → `byo` re-enable must
 *     propagate on the very next read, and a frozen policy would defeat that.
 *  3. **Any EVALUABLE fresh answer wins outright.** `true` and `false` both replace the cache, so an
 *     administrator granting `ai:assist` un-sticks the deny the moment that user's next authenticated
 *     read returns `true`. The escape hatch is signing in, not clearing extension state.
 *  4. **`cached === null` (the first ever read) is a plain pass-through.**
 *  5. **The fresh bit is NARROWED before anything is decided** ({@link evaluatedPermission}). Any
 *     non-boolean — `null`, or the `undefined` a 200 that OMITS the field produces — is treated as
 *     "not evaluated" and normalized to `null` on the way out, so a degraded answer can neither slip
 *     past the guard nor be written to the cache in a shape no later comparison can match.
 *
 * Consequence, stated so it is a decision and not a surprise: once a `false` is cached, every later
 * `null` preserves it. A user whose permission is granted later but who holds no valid session sees
 * assistance disabled until the engine answers `true` for them. That is the fail-CLOSED direction and
 * matches SEC-022's intent, but there is no "clear cached policy" affordance in the extension.
 */
export function mergeAuthoritativePolicy(cached: AiPolicy | null, fresh: AiPolicy): AiPolicy {
  const permitted = evaluatedPermission(fresh.assistPermitted);
  if (permitted === null && cached?.assistPermitted === false) {
    return { ...fresh, assistPermitted: false };
  }
  return { ...fresh, assistPermitted: permitted };
}

/**
 * Apply the gating rules to a resolved policy. `enabled` false means the chat handler must not call
 * the model and should stream `message` instead. The only ENABLED case is BYO with the permission
 * granted or unknown (null) — BYO is PHI-safe by construction (code-only context).
 *
 * It lives here rather than in aiPolicy.ts (it is re-exported from there, so every caller is unchanged)
 * because it is the PREDICATE {@link mergeAuthoritativePolicy} feeds. Asserting the merge rule without
 * asserting that the retained bit actually reaches this gate would prove only that a field survived in
 * a struct — and that coupling has to be provable in the node-side runner that runs on every CI leg.
 */
export function assistantState(p: AiPolicy): { enabled: boolean; message?: string } {
  if (p.mode === "off") {
    return { enabled: false, message: "AI assistance is turned off by your MessageFoundry policy." };
  }
  if (p.mode === "unverified") {
    // Engine unreachable + no cached policy + no positive local CLI policy: fail closed so a central
    // "off" / ai:assist deny can't be bypassed by going offline (SEC-022).
    return {
      enabled: false,
      message:
        "MessageFoundry AI policy could not be verified (engine unreachable) — assistance is disabled until it can be confirmed.",
    };
  }
  if (p.mode === "managed_endpoint") {
    // Engine-brokered path (ADR 0135): the ENGINE brokers the call to the customer-managed / self-hosted
    // LLM under central per-use audit. Enabled when the caller holds ai:assist (or it is unknown offline);
    // chat.ts routes this mode to the engine broker instead of the local vscode.lm model.
    if (p.assistPermitted === false) {
      return { enabled: false, message: "Your role does not include the ai:assist permission." };
    }
    return { enabled: true };
  }
  if (p.mode === "managed_claude" || p.mode === "managed_claude_baa") {
    return {
      enabled: false,
      message:
        "Your MessageFoundry policy uses a managed AI provider, which this extension version does not yet support. Assistance is unavailable.",
    };
  }
  if (p.mode === "byo" && p.assistPermitted === false) {
    return { enabled: false, message: "Your role does not include the ai:assist permission." };
  }
  // BYO with assistPermitted true OR null (RBAC not evaluable offline) — allowed.
  return { enabled: true };
}
