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
  environment: string;
  // null = RBAC could not be evaluated (no/invalid token under enabled auth, or resolved offline).
  assistPermitted: boolean | null;
  reason: string | null;
}

// Snake_case wire shape shared by GET /ai/policy and `messagefoundry ai-policy --json`.
interface AiPolicyWire {
  mode: string;
  data_scope: string;
  environment: string;
  assist_permitted: boolean | null;
  reason: string | null;
}

// Conservative built-in used only when both the engine and the CLI are unavailable: BYO + code_only
// keeps the existing PHI-safe assistant working without assuming any elevated policy.
const DEFAULT_POLICY: AiPolicy = {
  mode: "byo",
  dataScope: "code_only",
  environment: "prod",
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
 * Resolve the effective AI policy. Order: (a) the running engine [authoritative — includes the
 * identity-dependent `assist_permitted`]; (b) the local CLI [reads messagefoundry.toml; assist bit
 * is null offline]; (c) a conservative built-in default so the safe BYO assistant still works.
 */
export async function resolveAiPolicy(): Promise<AiPolicy> {
  try {
    return fromWire(await getJson<AiPolicyWire>(engineUrl(), "/ai/policy"));
  } catch {
    // Engine unreachable or errored — fall back to the offline CLI view of the local config.
  }
  try {
    return fromWire(await runJson<AiPolicyWire>(["ai-policy"], workspaceDir()));
  } catch {
    // CLI unavailable too (no Python / no workspace) — use the safe built-in default.
  }
  return DEFAULT_POLICY;
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
export async function showAiPolicy(): Promise<void> {
  const p = await resolveAiPolicy();
  const permitted =
    p.assistPermitted === null ? "unknown" : p.assistPermitted ? "yes" : "no";
  const reason = p.reason ? ` — ${p.reason}` : "";
  void vscode.window.showInformationMessage(
    `MessageFoundry AI policy: mode=${p.mode}, data_scope=${p.dataScope}, ` +
      `environment=${p.environment}, assist_permitted=${permitted}${reason}`,
  );
}
