// AI-assistance policy resolution for the IDE. The policy is centrally governed by the engine; the
// IDE reads it (never sets it) and gates the @messagefoundry chat assistant accordingly. Resolution
// is authoritative-engine-first, falling back to the local CLI (which reads messagefoundry.toml) when
// the engine is unreachable.
//
// The policy has TWO halves and they are answered differently:
//   - `mode` is identity-INDEPENDENT, so a central "off" is honored even by a tokenless client;
//   - `assist_permitted` is identity-DEPENDENT — the engine answers `null` to anyone it cannot
//     attribute — so this read attaches the cached bearer (BACKLOG #330). A degraded/unattributed
//     answer must not overwrite a cached deny; that is mergeAuthoritativePolicy's job.
import * as vscode from "vscode";
import { peekToken } from "./auth";
import { type AiPolicy, evaluatedPermission, mergeAuthoritativePolicy } from "./aiPolicyModel";
import { engineUrl, runJson, workspaceDir } from "./cli";
import { getJson } from "./engineClient";
import { ASSIST_GATE_PLAN } from "./engineStatusModel";
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

// globalState key holding the last authoritative (engine) policy, so a previously-seen central
// "off" / ai:assist deny is not overridable simply by taking the engine offline (SEC-022).
const LAST_POLICY_KEY = "messagefoundry.lastAiPolicy";

// Fail-closed fallback used when the engine is unreachable, no cached authoritative policy exists,
// AND the local CLI can't positively confirm a policy: assistance is DISABLED rather than silently
// re-enabling BYO. The "unverified" mode is mapped to {enabled:false} by assistantState (SEC-022,
// CWE-636 — an org-set central "off" must not fail open just because the engine is unreachable).
const UNVERIFIED_POLICY: AiPolicy = {
  mode: "unverified",
  dataScope: "code_only",
  environment: null,
  assistPermitted: null,
  reason: null,
};

/**
 * Wire → resolved policy. `AiPolicyWire` is a claim about a response, not a guarantee: `JSON.parse`
 * validates nothing, so `assist_permitted` is NARROWED here rather than copied. This is the boundary
 * for BOTH authoritative sources — the engine read and the CLI fallback — and only the former also
 * passes through {@link mergeAuthoritativePolicy}, so the narrowing has to happen here to cover both.
 */
function fromWire(w: AiPolicyWire): AiPolicy {
  return {
    mode: w.mode,
    dataScope: w.data_scope,
    environment: w.environment,
    assistPermitted: evaluatedPermission(w.assist_permitted),
    reason: w.reason,
  };
}

/**
 * Pick the policy when the authoritative engine is unreachable. Pure + testable. Order:
 *   (a) the last cached authoritative (engine) policy, if any — so a previously-seen central "off" /
 *       ai:assist deny survives going offline; else
 *   (b) the local CLI's policy, if it positively returned one (it may itself carry mode "off"); else
 *   (c) the fail-closed UNVERIFIED policy (assistance disabled) — NEVER silently re-enable BYO.
 */
export function pickOfflinePolicy(cached: AiPolicy | null, cli: AiPolicy | null): AiPolicy {
  if (cached) {
    return cached;
  }
  if (cli) {
    return cli;
  }
  return UNVERIFIED_POLICY;
}

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
}

/**
 * Production wiring.
 *
 * `readToken` is {@link peekToken} and must NEVER become `ensureToken`: a chat turn resolves the policy
 * before every request, and `ensureToken` would pop an interactive sign-in modal out of it. The two
 * functions are structurally identical, so the type system cannot tell them apart — the control is the
 * test that asserts this field IS `peekToken` by identity, not this comment.
 */
export const DEFAULT_AI_POLICY_IO: AiPolicyIo = {
  url: engineUrl,
  readToken: peekToken,
  getPolicy: (url, route, token) => getJson<AiPolicyWire>(url, route, token),
  getCliPolicy: () => runJson<AiPolicyWire>(["ai-policy"], workspaceDir()),
};

/**
 * Resolve the effective AI policy. Order: (a) the running engine [authoritative — includes the
 * identity-dependent `assist_permitted`; cached on success]; (b) when the engine is unreachable, the
 * last cached authoritative policy; (c) the local CLI [reads messagefoundry.toml]; (d) a fail-closed
 * "unverified" policy (assistance disabled) so a central "off" can't be bypassed by going offline.
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
  try {
    const url = io.url();
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
    // the deny and nothing else; see mergeAuthoritativePolicy for why it is one-way.
    const merged = mergeAuthoritativePolicy(
      ctx.globalState.get<AiPolicy>(LAST_POLICY_KEY) ?? null,
      fresh,
    );
    await ctx.globalState.update(LAST_POLICY_KEY, merged); // remember the authoritative answer
    return merged;
  } catch {
    // Engine unreachable or errored — fall back to the cached authoritative / CLI / fail-closed view.
  }
  const cached = ctx.globalState.get<AiPolicy>(LAST_POLICY_KEY) ?? null;
  let cli: AiPolicy | null = null;
  try {
    cli = fromWire(await io.getCliPolicy());
  } catch {
    // CLI unavailable too (no Python / no workspace / untrusted) — leave cli null.
  }
  return pickOfflinePolicy(cached, cli);
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
