// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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
 * The cached form: the policy plus when the engine answered it, in epoch milliseconds. `cachedAt`
 * is optional because a cache written before BACKLOG #1154 has none, and that cache is read as
 * too old to vouch for anything.
 */
export interface CachedAiPolicy extends AiPolicy {
  cachedAt?: number;
}

/**
 * How long a cached answer that ENABLES assistance is trusted once the engine is unreachable: 12
 * hours, the same figure as the engine's default `[auth].session_absolute_hours`. It counts from
 * when the engine answered, not from a session's start, so it is a fixed bound and not a session's
 * remaining life; a tokenless answer has no session at all. The bound applies only while the
 * engine is unreachable. It forces no sign-in: a reachable engine answering a tokenless read
 * says "unknown", `byo` treats that as allowed, and the answer is cached afresh. This is a bound,
 * not a fix: inside it, a withdrawn grant still does not reach an offline IDE. A cached answer
 * that DISABLES assistance has no age limit.
 */
export const CACHED_PERMIT_MAX_AGE_MS = 12 * 60 * 60 * 1000;

/**
 * The fail-closed policy for when nothing can vouch for one: the engine is unreachable, and either
 * no authoritative answer is cached and the local CLI gives none, or the cached answer that enabled
 * assistance is too old. {@link assistantState} disables assistance for it (SEC-022, CWE-636).
 */
export const UNVERIFIED_POLICY: AiPolicy = {
  mode: "unverified",
  dataScope: "code_only",
  environment: null,
  assistPermitted: null,
  reason: null,
};

/**
 * What a cached authoritative policy may still say once the engine is unreachable (BACKLOG #1154,
 * ASVS 8.3.2). Before this, the cache answered with no age limit, so a withdrawn `ai:assist` never
 * reached an IDE that could not reach the engine.
 *
 *  1. **A cached DISABLE is returned however old it is.** That is the SEC-022 rule, and it does not
 *     change: a central "off" or an `ai:assist` deny must survive going offline.
 *  2. **A cached ENABLE is returned only while it is no older than {@link CACHED_PERMIT_MAX_AGE_MS}.**
 *     Past that, or with no `cachedAt`, or with a `cachedAt` in the future (a clock stepped back),
 *     the answer is {@link UNVERIFIED_POLICY}, which disables assistance.
 *
 * "Enable" and "disable" are what {@link assistantState} says, so a mode added later is sorted the
 * same way the gate sorts it. The returned policy never carries `cachedAt`.
 */
export function cachedPolicyOffline(cached: CachedAiPolicy, nowMs: number): AiPolicy {
  const { cachedAt, ...policy } = cached;
  if (!assistantState(policy).enabled) {
    return policy;
  }
  if (typeof cachedAt !== "number") {
    return UNVERIFIED_POLICY;
  }
  const age = nowMs - cachedAt;
  return age >= 0 && age <= CACHED_PERMIT_MAX_AGE_MS ? policy : UNVERIFIED_POLICY;
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
 * Narrow a wire `mode` to a string (BACKLOG #5406), for the same reason as
 * {@link evaluatedPermission}: a 200 can omit it or carry a non-string. Anything but a string becomes
 * `"unrecognized"`, a mode {@link assistantState} does not name and so disables, and which every
 * reader, the gate and "Show AI Policy" alike, then sees the same way.
 */
export function narrowMode(v: unknown): string {
  return typeof v === "string" ? v : "unrecognized";
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
 * the model and should stream `message` instead. The only ENABLED cases are `byo` and
 * `managed_endpoint` with the permission granted or unknown (null) — BYO is PHI-safe by construction
 * (code-only context). Every other mode, named here or not, disables assistance.
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
  if (p.mode === "managed_claude" || p.mode === "managed_claude_baa") {
    return {
      enabled: false,
      message:
        "Your MessageFoundry policy uses a managed AI provider, which this extension version does not yet support. Assistance is unavailable.",
    };
  }
  // managed_endpoint is the engine-brokered path (ADR 0135): the ENGINE brokers the call to the
  // customer-managed / self-hosted LLM under central per-use audit, and chat.ts routes it there
  // instead of the local vscode.lm model.
  // The permission comes before the allow-list below, so an ai:assist deny is named as such for any
  // mode that reaches here; off, unverified and the managed modes have already answered above.
  if (p.assistPermitted === false) {
    return { enabled: false, message: "Your role does not include the ai:assist permission." };
  }
  if (p.mode !== "byo" && p.mode !== "managed_endpoint") {
    // An ALLOW-list, not a deny-list (BACKLOG #5406): a mode this version does not name -- a newer
    // engine's, or a missing or malformed one -- disables assistance rather than falling through to
    // the local model (SEC-022, CWE-636).
    return {
      enabled: false,
      message:
        "Your MessageFoundry policy does not give an AI mode this extension version recognizes. Assistance is disabled.",
    };
  }
  // byo or managed_endpoint with assistPermitted true OR null (RBAC not evaluable offline) — allowed.
  return { enabled: true };
}

/**
 * The globalState key prefix for a cached authoritative policy. The key is per ENGINE (BACKLOG
 * #5564): with one unscoped key, the answer one engine gave stood in for another, so a permit cached
 * from engine A enabled assistance while engine B was unreachable, and a deny cached from B was
 * replaced by A's answer. Each engine's cache now holds only that engine's own answer. The one state
 * that crosses engines is a deny, and it goes through the deny carrier ({@link AI_POLICY_DENY_KEY}),
 * which also migrates a deny held under the key written before this change.
 */
export const AI_POLICY_CACHE_PREFIX = "messagefoundry.lastAiPolicy@";

/**
 * Pick the policy when the authoritative engine is unreachable. Pure + testable. Order:
 *   (a) the last cached authoritative policy from THIS engine, if any, as {@link cachedPolicyOffline}
 *       lets it stand — so a previously-seen central "off" / ai:assist deny survives going offline,
 *       and a cached answer that enables assistance stops doing so once it is too old (BACKLOG
 *       #1154); else
 *   (b) the local CLI's policy, if it positively returned one (it may itself carry mode "off"), but
 *       only when no engine target is configured and the IDE has never held an engine's answer
 *       (`targetConfigured` and `answeredBefore` below); else
 *   (c) the fail-closed UNVERIFIED policy (assistance disabled) — NEVER silently re-enable BYO.
 *
 * An expired cache does NOT fall through to (b). An IDE that holds a cache has heard from the
 * engine, which is the authority; a local file must not outrank it once its answer expires.
 *
 * `targetConfigured` (BACKLOG #5564): the cache is per engine, so an operator-configured target that
 * is unreachable and has never answered finds no cache. The local CLI is not that engine and must
 * not answer for it, or retargeting would bypass a deny; such a target fails closed. The CLI stays
 * the fallback only for the default target, where the local file is the policy's nearest source.
 *
 * `answeredBefore` ({@link heldAuthoritativeAnswer}): once the IDE has held any engine's answer, the
 * CLI does not answer for the default target either. Before the per-engine cache, the one cache held
 * that answer there, so an expired permit or a disabling mode such as `managed_claude` disabled
 * assistance; with the CLI answering, clearing a configured target or upgrading would let a local
 * file outrank an expired engine answer, against the rule above.
 */
export function pickOfflinePolicy(
  cached: CachedAiPolicy | null,
  cli: AiPolicy | null,
  nowMs: number = Date.now(),
  targetConfigured: boolean = false,
  answeredBefore: boolean = false,
): AiPolicy {
  if (cached) {
    return cachedPolicyOffline(cached, nowMs);
  }
  if (cli && !targetConfigured && !answeredBefore) {
    return cli;
  }
  return UNVERIFIED_POLICY;
}

/**
 * The globalState key for the policy cached from the engine at `url`. The URL is canonicalized so
 * one engine spelled two ways shares one entry: the origin, which lowercases the scheme and host and
 * drops a default port, plus the path with trailing slashes removed. The path stays in because the
 * engine client appends each route to it, so two engines behind one origin at different paths are
 * two engines. A URL that does not parse, or has no origin, is keyed by its trimmed text.
 */
export function aiPolicyCacheKey(url: string): string {
  const text = url.trim();
  let base = text.replace(/\/+$/, "");
  try {
    const u = new URL(text);
    if (u.origin !== "null") {
      base = u.origin + u.pathname.replace(/\/+$/, "");
    }
  } catch {
    // Not a URL: keep the trimmed text, which still separates one setting value from another.
  }
  return AI_POLICY_CACHE_PREFIX + base;
}

/**
 * The globalState key of the deny carrier (BACKLOG #5564). With the per-engine cache alone, a deny
 * stayed behind when the target changed: clear `engineUrl` back to the default, or spell the same
 * engine another way, and the new key held no deny. The carrier records every central "off" and
 * every `ai:assist` deny an engine answers, with the engine that issued it, so the deny reaches each
 * target that has no authoritative answer of its own. {@link carryDeniesOnline} and
 * {@link carryDeniesOffline} say what applies it and what clears it.
 */
export const AI_POLICY_DENY_KEY = "messagefoundry.aiPolicyDenies";

/**
 * The one unscoped cache key used before BACKLOG #5564. A deny it holds is carried into
 * {@link AI_POLICY_DENY_KEY}, and the key is deleted only once that write has succeeded.
 */
export const LEGACY_AI_POLICY_KEY = "messagefoundry.lastAiPolicy";

/**
 * The issuer recorded for a deny migrated from {@link LEGACY_AI_POLICY_KEY}, which never named the
 * engine that answered it. A real issuer is a cache key and starts with
 * {@link AI_POLICY_CACHE_PREFIX}, so the two cannot collide.
 */
export const UNKNOWN_DENY_ISSUER = "unknown";

/** The carried denies: the issuer (an engine's cache key, or {@link UNKNOWN_DENY_ISSUER}) to its deny. */
export type CarriedDenies = Record<string, AiPolicy>;

/** The globalState surface the carrier needs; vscode's Memento satisfies it. */
export interface PolicyStore {
  get<T>(key: string): T | undefined;
  update(key: string, value: unknown): PromiseLike<void>;
  keys(): readonly string[];
}

/**
 * Written before {@link LEGACY_AI_POLICY_KEY} is deleted, so the IDE still knows it once held an
 * engine's answer after the old key is gone ({@link heldAuthoritativeAnswer}).
 */
export const AI_POLICY_ANSWERED_KEY = "messagefoundry.aiPolicyAnswered";

/**
 * Whether the IDE has ever held an authoritative engine answer: any per-engine cache key, the old
 * unscoped key, or the marker written when that key is deleted. While it has, the local CLI does not
 * answer for an unreachable target ({@link pickOfflinePolicy}). A store whose keys cannot be read
 * counts as having held one, which fails closed.
 */
export function heldAuthoritativeAnswer(store: PolicyStore): boolean {
  try {
    return store
      .keys()
      .some((k) => k.startsWith(AI_POLICY_CACHE_PREFIX) || k === LEGACY_AI_POLICY_KEY || k === AI_POLICY_ANSWERED_KEY);
  } catch {
    return true;
  }
}

/** A central "off" or an `ai:assist` deny: the two answers the carrier records. */
export function isPolicyDeny(p: AiPolicy): boolean {
  return p.mode === "off" || p.assistPermitted === false;
}

function policyOnly(p: CachedAiPolicy): AiPolicy {
  const { cachedAt: _cachedAt, ...policy } = p;
  return policy;
}

/**
 * What a carried entry that is not a deny-shaped object stands for. The carrier is written only
 * with denies, so any other value is corruption or a hand edit, and it cannot say what was carried.
 * It fails closed: an `ai:assist` deny under the unverified mode, so the gate disables assistance
 * with the could-not-verify message, and only its issuer's authoritative permit clears it.
 */
const MALFORMED_DENY: AiPolicy = { ...UNVERIFIED_POLICY, assistPermitted: false };

/** A carried entry as the carrier may use it: a deny-shaped object the gate disables, as it is;
 *  anything else as {@link MALFORMED_DENY}. The gate check is kept beside the gate's own allow-list
 *  (BACKLOG #5406), so "never permits" does not rest on how the gate is shaped. Never throws, and
 *  never permits. */
function carriedEntry(value: unknown): AiPolicy {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return MALFORMED_DENY;
  }
  const p = value as AiPolicy;
  return typeof p.mode === "string" && isPolicyDeny(p) && !assistantState(p).enabled ? p : MALFORMED_DENY;
}

// Every read-modify-write of the carrier runs on this one chain, so two resolves that overlap cannot
// both read the old map and have the later write drop the earlier one's deny.
let carrierChain: Promise<unknown> = Promise.resolve();

function withCarrier<T>(
  store: PolicyStore,
  step: (carried: CarriedDenies) => { next: CarriedDenies; result: T },
): Promise<T> {
  const run = carrierChain.then(async () => {
    const stored = store.get<Record<string, unknown>>(AI_POLICY_DENY_KEY);
    // Each entry is checked, not only the map: one entry that is not a deny-shaped object would
    // otherwise throw in isPolicyDeny on every resolve, or slip past it as a non-deny. A stored map
    // that is not a plain object cannot say what it carried either, so it fails closed as one
    // malformed deny with an unknown issuer, which any engine's authoritative permit clears.
    let carried: CarriedDenies;
    if (stored === undefined) {
      carried = {};
    } else if (stored !== null && typeof stored === "object" && !Array.isArray(stored)) {
      carried = Object.fromEntries(Object.entries(stored).map(([key, value]) => [key, carriedEntry(value)]));
    } else {
      carried = { [UNKNOWN_DENY_ISSUER]: MALFORMED_DENY };
    }
    let migrated = false;
    // The unscoped key, once. A deny in it is carried with an unknown issuer, which any engine's
    // authoritative permit clears: origin/main's rule for that key.
    const legacy = store.get<CachedAiPolicy>(LEGACY_AI_POLICY_KEY);
    if (legacy !== undefined && legacy !== null && typeof legacy === "object" && isPolicyDeny(legacy)) {
      carried = { ...carried, [UNKNOWN_DENY_ISSUER]: carriedEntry(policyOnly(legacy)) };
      migrated = true;
    }
    const { next, result } = step(carried);
    let persisted = true;
    if (migrated || JSON.stringify(next) !== JSON.stringify(carried)) {
      try {
        await store.update(AI_POLICY_DENY_KEY, next);
      } catch {
        // The result above already carries every deny read or recorded, so it is returned and
        // still gates. Failing the resolve would only send the caller to a fallback with less.
        persisted = false;
      }
    }
    // The old key goes only once the carrier holding its deny is written: deleted first, a failed
    // write would lose the deny, which fails open. Kept, it is migrated again next time.
    // The marker goes first, so a deleted old key still bars the CLI; a failed marker write keeps
    // the old key, which bars it too.
    if (legacy !== undefined && persisted) {
      try {
        await store.update(AI_POLICY_ANSWERED_KEY, true);
        await store.update(LEGACY_AI_POLICY_KEY, undefined);
      } catch {
        // Kept, it is migrated again on the next resolve, which retries the delete. The result
        // above is what this resolve computed; failing it would send an answered target to the
        // offline path.
      }
    }
    return result;
  });
  // A failed step must not leave every later resolve behind a rejected chain.
  carrierChain = run.catch(() => undefined);
  return run;
}

/**
 * The carrier's step for a FRESH answer from the engine keyed `issuer`. `fresh` is the answer, and
 * `merged` is it merged over that engine's own cache (what is cached for it).
 *
 *  1. **Clearing.** A carried deny is cleared only by an authoritative permit: a fresh answer that,
 *     merged over the deny, enables assistance. Only the engine that issued the deny can clear it; a
 *     deny with {@link UNKNOWN_DENY_ISSUER} is cleared by any engine.
 *  2. **Recording.** A `merged` that is a deny is recorded under `issuer`.
 *  3. **Applying.** Every carried deny is merged over the answer. So an `ai:assist` deny reaches an
 *     answer that could not evaluate the permission (`null`), such as the same engine at an alias URL
 *     the bearer is not cached for. An evaluated `true` or `false` is that engine's own answer and
 *     stands, and so does its `mode`, which is identity-independent and always comes fresh.
 *
 * Returns the policy to gate on. The engine's own cache keeps `merged`, not this.
 */
export function carryDeniesOnline(
  store: PolicyStore,
  issuer: string,
  fresh: AiPolicy,
  merged: AiPolicy,
): Promise<AiPolicy> {
  return withCarrier(store, (carried) => {
    const next: CarriedDenies = {};
    for (const [key, deny] of Object.entries(carried)) {
      const clearable = key === issuer || key === UNKNOWN_DENY_ISSUER;
      if (!(clearable && assistantState(mergeAuthoritativePolicy(deny, fresh)).enabled)) {
        next[key] = deny;
      }
    }
    if (isPolicyDeny(merged)) {
      next[issuer] = policyOnly(merged);
    }
    const result = Object.values(next).reduce((p, deny) => mergeAuthoritativePolicy(deny, p), merged);
    return { next, result };
  });
}

/**
 * The carrier's step when the target is unreachable. `offline` is what {@link pickOfflinePolicy}
 * chose. Any carried deny applies, whichever engine issued it: an unreachable target has no
 * authoritative answer of its own, and neither a cached permit nor the local CLI may outrank a deny
 * an engine gave. A choice that already disables assistance is returned as it is, except the
 * unverified one, which a carried deny replaces so the gate names the engine's reason.
 */
export function carryDeniesOffline(store: PolicyStore, offline: AiPolicy): Promise<AiPolicy> {
  return withCarrier(store, (carried) => {
    if (!assistantState(offline).enabled && offline.mode !== UNVERIFIED_POLICY.mode) {
      return { next: carried, result: offline };
    }
    const deny = Object.values(carried).find(isPolicyDeny);
    return { next: carried, result: deny === undefined ? offline : { ...deny } };
  });
}

/**
 * What the chat says when an engine-brokered request got no reply because `withAuth` answered
 * undefined (BACKLOG #5407). `sent` is whether the request itself went out. Before it goes, that
 * answer means a cancelled sign-in or a target the gate refused. After it, it means the engine
 * refused the token with a 401 and signing in again was cancelled or failed, so the prompt and any
 * code attached to it did reach the engine, and saying nothing was sent would be false.
 */
export function brokeredNoReplyNotice(sent: boolean): string {
  return sent
    ? "_The request was sent to the MessageFoundry engine, with your prompt and any code attached to it, but " +
        "the engine refused the sign-in it carried and signing in again did not complete, so no reply was " +
        "received. Sign in to the engine and ask again._"
    : "_Nothing was sent: sign in to the MessageFoundry engine to use engine-brokered AI assistance, " +
        "or, if an error said the engine address was refused, correct that address._";
}

/** The default of `messagefoundry.ai.contextCharLimit`, as the manifest declares it. */
export const DEFAULT_CONTEXT_CHAR_LIMIT = 8000;

/** The scopes of `messagefoundry.ai.contextCharLimit` that {@link contextCharLimitOf} reads: VS
 *  Code's `inspect()` answer. A folder value is not read, as the setting is read with no resource. */
export interface ContextCharLimitScopes {
  readonly defaultValue?: unknown;
  readonly globalValue?: unknown;
  readonly workspaceValue?: unknown;
}

/** `v` as a character count: a finite number of zero or more, rounded down, else undefined. */
function charCount(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) && v >= 0 ? Math.floor(v) : undefined;
}

/**
 * The bound on editor code a chat request attaches (BACKLOG #5404 item 2). The user's own value,
 * else the manifest default, else {@link DEFAULT_CONTEXT_CHAR_LIMIT}, sets the bound; a workspace
 * value, which a repository's `.vscode/settings.json` can set, applies only when it is LOWER. A
 * repository may so tighten what leaves for the model provider (say `0`, graph names only), but not
 * widen it past what the operator chose. That is why the setting is not in the manifest's
 * `restrictedConfigurations`: Restricted Mode would drop a tightening workspace value too. A value
 * that is not a count of zero or more is ignored, at any scope, for the next one down. No answer at
 * all (`seen` undefined) gives the default.
 */
export function contextCharLimitOf(seen: ContextCharLimitScopes | undefined): number {
  const base = charCount(seen?.globalValue) ?? charCount(seen?.defaultValue) ?? DEFAULT_CONTEXT_CHAR_LIMIT;
  const ws = charCount(seen?.workspaceValue);
  return ws !== undefined && ws < base ? ws : base;
}
