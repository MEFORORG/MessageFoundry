// AI-assistance policy resolution for the IDE. The policy is centrally governed by the engine; the
// IDE reads it (never sets it) and gates the @messagefoundry chat assistant accordingly. Resolution
// is authoritative-engine-first so a central "off" is honored even by a tokenless client, falling
// back to the local CLI (which reads messagefoundry.toml) when the engine is unreachable.
import * as vscode from "vscode";
import { engineUrl, runJson, workspaceDir } from "./cli";
import { getJson } from "./engineClient";

export interface AiPolicy {
  mode: string;
  dataScope: string;
  environment: string | null;
  // null = RBAC could not be evaluated (no/invalid token under enabled auth, or resolved offline).
  assistPermitted: boolean | null;
  reason: string | null;
}

// Snake_case wire shape shared by GET /ai/policy and `messagefoundry ai-policy --json`.
interface AiPolicyWire {
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

function fromWire(w: AiPolicyWire): AiPolicy {
  return {
    mode: w.mode,
    dataScope: w.data_scope,
    environment: w.environment,
    assistPermitted: w.assist_permitted,
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
 * Resolve the effective AI policy. Order: (a) the running engine [authoritative — includes the
 * identity-dependent `assist_permitted`; cached on success]; (b) when the engine is unreachable, the
 * last cached authoritative policy; (c) the local CLI [reads messagefoundry.toml]; (d) a fail-closed
 * "unverified" policy (assistance disabled) so a central "off" can't be bypassed by going offline.
 */
export async function resolveAiPolicy(ctx: vscode.ExtensionContext): Promise<AiPolicy> {
  try {
    const policy = fromWire(await getJson<AiPolicyWire>(engineUrl(), "/ai/policy"));
    await ctx.globalState.update(LAST_POLICY_KEY, policy); // remember the authoritative answer
    return policy;
  } catch {
    // Engine unreachable or errored — fall back to the cached authoritative / CLI / fail-closed view.
  }
  const cached = ctx.globalState.get<AiPolicy>(LAST_POLICY_KEY) ?? null;
  let cli: AiPolicy | null = null;
  try {
    cli = fromWire(await runJson<AiPolicyWire>(["ai-policy"], workspaceDir()));
  } catch {
    // CLI unavailable too (no Python / no workspace / untrusted) — leave cli null.
  }
  return pickOfflinePolicy(cached, cli);
}

/**
 * Apply the gating rules to a resolved policy. `enabled` false means the chat handler must not call
 * the model and should stream `message` instead. The only ENABLED case is BYO with the permission
 * granted or unknown (null) — BYO is PHI-safe by construction (code-only context).
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
  if (p.mode === "byo" && p.assistPermitted === false) {
    return { enabled: false, message: "Your role does not include the ai:assist permission." };
  }
  // BYO with assistPermitted true OR null (RBAC not evaluable offline) — allowed.
  return { enabled: true };
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
