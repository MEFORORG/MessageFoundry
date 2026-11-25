// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// AI-assistance policy resolution for the IDE. The policy is centrally governed by the engine; the
// IDE reads it (never sets it) and gates the @messagefoundry chat assistant accordingly. Resolution
// is authoritative-engine-first, falling back, when the engine is unreachable, to that engine's
// cached answer, and to the local CLI (which reads `messagefoundry.serviceConfig`, BACKLOG #5405)
// only where pickOfflinePolicy allows it.
//
// The policy has TWO halves and they are answered differently:
//   - `mode` is identity-INDEPENDENT, so a central "off" is honored even by a tokenless client;
//   - `assist_permitted` is identity-DEPENDENT — the engine answers `null` to anyone it cannot
//     attribute — so this read attaches the cached bearer (BACKLOG #330). A degraded/unattributed
//     answer must not overwrite a cached deny; that is mergeAuthoritativePolicy's job.
import * as vscode from "vscode";
import { peekToken } from "./auth";
import {
  type AiPolicy,
  type CachedAiPolicy,
  aiPolicyCacheKey,
  carryDeniesOffline,
  carryDeniesOnline,
  evaluatedPermission,
  heldAuthoritativeAnswer,
  mergeAuthoritativePolicy,
  narrowMode,
  pickOfflinePolicy,
} from "./aiPolicyModel";
import {
  engineTargetIsSet,
  engineUrl,
  environments,
  pathSettingLinkEscape,
  runJson,
  workspaceDir,
  writerCheckSetting,
} from "./cli";
import { aiPolicyCliPlan } from "./engineControlModel";
import { getJson } from "./engineClient";
import { ASSIST_GATE_PLAN, resolveEngineStatusTarget } from "./engineStatusModel";
import { assertTargetAllowed } from "./engineTarget";

// The policy shape lives in the zero-import aiPolicyModel so the merge rule below it can be asserted
// by the node-side runner that executes on every CI leg (this module imports vscode, so its own test
// file is `--ignore`d by `test:unit`). Re-exported in TYPE form: esbuild bundles with isolatedModules
// semantics, where a value-form re-export of a type-only symbol fails at BUNDLE time while
// `tsc --noEmit` stays green. Existing importers (chat.ts, extension.ts, the tests) are unchanged.
export type { AiPolicy } from "./aiPolicyModel";
// `assistantState` moved there too: it is the predicate the merge rule feeds, and the two are only
// meaningful asserted together. Value-form re-export (it IS a value), so chat.ts and the existing
// ai-policy.test.ts import sites are untouched — ADR 0035 AC-5's test pointer stays valid.
export { assistantState } from "./aiPolicyModel";

// Snake_case wire shape shared by GET /ai/policy and `messagefoundry ai-policy --json`.
export interface AiPolicyWire {
  mode: string;
  data_scope: string;
  environment: string | null;
  assist_permitted: boolean | null;
  reason: string | null;
}

// The last authoritative (engine) policy is kept in globalState, so a previously-seen central "off" /
// ai:assist deny is not overridable simply by taking the engine offline (SEC-022). It is stamped with
// when the engine answered, so a cached answer that ENABLES assistance expires (BACKLOG #1154; see
// cachedPolicyOffline), and it is keyed by the engine that answered (aiPolicyCacheKey, BACKLOG #5564),
// so one engine's answer never stands in for another's. A DENY is the exception: the deny carrier
// (carryDeniesOnline / carryDeniesOffline) takes it to every target with no answer of its own, so a
// retarget or another spelling of the URL cannot leave it behind.

/**
 * Wire → resolved policy. `AiPolicyWire` is a claim about a response, not a guarantee: `JSON.parse`
 * validates nothing, so `assist_permitted` is NARROWED here rather than copied. This is the boundary
 * for BOTH authoritative sources — the engine read and the CLI fallback — and only the former also
 * passes through {@link mergeAuthoritativePolicy}, so the narrowing has to happen here to cover both.
 */
function fromWire(w: AiPolicyWire): AiPolicy {
  return {
    mode: narrowMode(w.mode),
    dataScope: w.data_scope,
    environment: w.environment,
    assistPermitted: evaluatedPermission(w.assist_permitted),
    reason: w.reason,
  };
}

// pickOfflinePolicy moved to the zero-import aiPolicyModel (BACKLOG #5564), so its fail-closed order
// is asserted on the node-side leg; re-exported so existing importers are unchanged.
export { pickOfflinePolicy } from "./aiPolicyModel";

/**
 * The injectable IO seam for {@link resolveAiPolicy}. It exists so the fetch-and-cache path — where
 * both of BACKLOG #330's defects lived — is testable at all: it was previously unreachable from a test
 * because every dependency was a direct module-level call.
 */
export interface AiPolicyIo {
  url: () => string;
  readToken: (ctx: vscode.ExtensionContext, url: string) => Promise<string | undefined>;
  getPolicy: (url: string, route: string, token: string | undefined) => Promise<AiPolicyWire>;
  getCliPolicy: () => Promise<AiPolicyWire>;
  /** The clock the cache is stamped and aged by, in epoch milliseconds. Defaults to `Date.now`. */
  now?: () => number;
  /** Whether the operator configured the engine target (`engineUrl` set, or any `environments`).
   *  Absent reads as not configured, the default target. See {@link pickOfflinePolicy}. */
  targetConfigured?: () => boolean;
}

/**
 * The engine the AI policy is read from, and the one an engine-brokered chat request goes to: the
 * engine the status bar and the live view target (BACKLOG #5564). With named `environments`
 * configured, that is the first environment, not `engineUrl`. Reading the policy from `engineUrl`
 * there asked a different engine than the one the IDE works against, so the target's central "off"
 * or `ai:assist` deny was never seen.
 */
export function aiPolicyEngineUrl(): string {
  return resolveEngineStatusTarget(engineUrl(), environments()).url;
}

/**
 * Production wiring.
 *
 * `readToken` is {@link peekToken} and must NEVER become `ensureToken`: a chat turn resolves the policy
 * before every request, and `ensureToken` would pop an interactive sign-in modal out of it. The two
 * functions are structurally identical, so the type system cannot tell them apart — the control is the
 * test that asserts this field IS `peekToken` by identity, not this comment.
 *
 * `url` is {@link aiPolicyEngineUrl}.
 */
export const DEFAULT_AI_POLICY_IO: AiPolicyIo = {
  url: aiPolicyEngineUrl,
  readToken: peekToken,
  getPolicy: (url, route, token) => getJson<AiPolicyWire>(url, route, token),
  getCliPolicy: () => {
    // A value the containment dropped gives no plan, as a writer refuses one (BACKLOG #5404): the
    // policy of the file used in its place is not the one the operator named, so it must not
    // enable assistance. Nothing dropped, the setting is set exactly when it is not the default.
    // So does one that leaves the workspace through a link (BACKLOG #5411): the CLI would read a
    // policy file outside it. A blank value is judged as the file the plan then names explicitly.
    const s = writerCheckSetting("serviceConfig");
    const usable = s.dropped === false && pathSettingLinkEscape("serviceConfig", s) === undefined;
    const plan = usable ? aiPolicyCliPlan(s.value, s.source !== "default", workspaceDir()) : undefined;
    // A rejection is "no CLI answer", which resolveAiPolicy turns into the unverified policy.
    return plan === undefined
      ? Promise.reject(new Error("no usable messagefoundry.serviceConfig for the offline AI policy"))
      : runJson<AiPolicyWire>(plan.args, plan.cwd);
  },
  targetConfigured: engineTargetIsSet,
};

/**
 * Resolve the effective AI policy. Order: (a) the running engine [authoritative — includes the
 * identity-dependent `assist_permitted`; cached on success, per engine]; (b) when the engine is
 * unreachable, that engine's last cached authoritative policy; (c) the local CLI [reads
 * `messagefoundry.serviceConfig`, and a missing file fails closed], only where {@link pickOfflinePolicy} allows it; (d) a fail-closed "unverified" policy (assistance disabled) so a central "off" can't be bypassed
 * by going offline or retargeting.
 * Every result passes through the deny carrier, so a deny any engine issued reaches a target that
 * has no authoritative answer of its own.
 *
 * The read is AUTHENTICATED (BACKLOG #330). `assist_permitted` is computed from the acting identity, so
 * a tokenless read can only ever answer `null` and the `ai:assist` deny branch could never fire — half
 * of ADR 0035's SEC-022 control was inert in the shipped code. The bearer is driven by
 * {@link ASSIST_GATE_PLAN}, the same mechanism that keeps the status bar's read of this very route
 * tokenless, so "who authenticates" is CI-asserted data rather than an argument at a call site.
 */
export async function resolveAiPolicy(
  ctx: vscode.ExtensionContext,
  io: AiPolicyIo = DEFAULT_AI_POLICY_IO,
): Promise<AiPolicy> {
  const now = io.now ?? Date.now;
  // The cache key names the engine asked (BACKLOG #5564). Undefined only if reading the target
  // threw, and then no engine's cache may answer for it.
  let cacheKey: string | undefined;
  try {
    const url = io.url();
    cacheKey = aiPolicyCacheKey(url);
    const plan = ASSIST_GATE_PLAN[0];
    // SEC-005 (ADR 0035 / engineTarget.ts): never send a bearer in clear to a non-loopback http://
    // target. Same shape as the liveStatus poll's guard. peekToken, never ensureToken — see
    // DEFAULT_AI_POLICY_IO. Driving the send off `plan.authenticated` is what makes the constant a
    // control on this side too: flipping it to false actually turns the bearer off.
    const token =
      plan.authenticated && assertTargetAllowed(url).ok ? await io.readToken(ctx, url) : undefined;
    const fresh = fromWire(await io.getPolicy(url, plan.route, token));
    // GUARDED write. An answer the engine could not attribute to an identity carries
    // `assist_permitted: null`, and writing that raw would overwrite a cached, authoritatively-observed
    // deny — a degraded read UPGRADING assistance a central policy had switched off. The merge keeps
    // the deny and nothing else; see mergeAuthoritativePolicy for why it is one-way. Only THIS
    // engine's cache is consulted (BACKLOG #5564): no state crosses engines.
    const merged = mergeAuthoritativePolicy(
      ctx.globalState.get<CachedAiPolicy>(cacheKey) ?? null,
      fresh,
    );
    // Remember the authoritative answer, stamped with when it was given (BACKLOG #1154).
    const stamped: CachedAiPolicy = { ...merged, cachedAt: now() };
    await ctx.globalState.update(cacheKey, stamped);
    // A deny another engine issued, or that this one answered at another spelling of its URL, still
    // reaches an answer that could not evaluate the permission (carryDeniesOnline).
    return await carryDeniesOnline(ctx.globalState, cacheKey, fresh, merged);
  } catch {
    // Engine unreachable or errored — fall back to the cached authoritative / CLI / fail-closed view.
  }
  const cached =
    cacheKey === undefined ? null : (ctx.globalState.get<CachedAiPolicy>(cacheKey) ?? null);
  // An operator-configured target that is unreachable and has no cache of its own fails closed:
  // the local CLI is not that engine (pickOfflinePolicy). Unreadable settings count as configured.
  let targetConfigured = true;
  try {
    targetConfigured = io.targetConfigured?.() ?? false;
  } catch {
    // Keep the fail-closed reading.
  }
  // Once any engine has answered, the local CLI does not answer for this target either: it must not
  // outrank an engine's answer that has expired or that disables (pickOfflinePolicy). Read before
  // the carrier runs, which may delete the old key.
  const answeredBefore = heldAuthoritativeAnswer(ctx.globalState);
  let cli: AiPolicy | null = null;
  // pickOfflinePolicy never reads the CLI's answer while a cache exists, for a configured target,
  // or once an engine has answered, so do not spawn it then.
  if (cached === null && !targetConfigured && !answeredBefore) {
    try {
      cli = fromWire(await io.getCliPolicy());
    } catch {
      // CLI unavailable too (no Python / no workspace / untrusted) — leave cli null.
    }
  }
  // Unreachable, so no answer of its own: any deny an engine issued applies (carryDeniesOffline).
  return carryDeniesOffline(
    ctx.globalState,
    pickOfflinePolicy(cached, cli, now(), targetConfigured, answeredBefore),
  );
}

/** Fetch the current policy and surface it to the user (command: messagefoundry.showAiPolicy). */
export async function showAiPolicy(ctx: vscode.ExtensionContext): Promise<void> {
  const p = await resolveAiPolicy(ctx);
  const permitted =
    p.assistPermitted === null ? "unknown" : p.assistPermitted ? "yes" : "no";
  const reason = p.reason ? ` — ${p.reason}` : "";
  void vscode.window.showInformationMessage(
    `MessageFoundry AI policy: mode=${p.mode}, data_scope=${p.dataScope}, ` +
      `environment=${p.environment}, assist_permitted=${permitted}${reason}`,
  );
}
