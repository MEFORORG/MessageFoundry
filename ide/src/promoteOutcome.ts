// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Pure (vscode-free) half of the promote flow's reload step: the `/config/reload` call and the words
// the promote shows for each outcome. Kept out of promote.ts, which imports vscode, so the node-only
// `test:unit` leg exercises it on every CI leg rather than only on the Windows integration leg
// (BACKLOG #1981). It imports only engineClient.ts, which is vscode-free for the same reason.
import { postApprovable, type Approvable } from "./engineClient";

/**
 * The fields of messagefoundry/api/models.py:ReloadResult (the /config/reload response) that the
 * promote reads. The engine also sends `degraded` and `failures`; reporting those is BACKLOG #2259.
 */
export interface ReloadResult {
  inbound: number;
  outbound: number;
  routers: number;
  handlers: number;
  running: boolean;
  dry_run: boolean;
}

/**
 * POST `/config/reload`. With `dryRun` it is the pre-flight, which the engine never holds; without
 * it, dual control may hold the swap for a second approver, and the result then says `held`.
 */
export function reloadConfig(
  baseUrl: string,
  configDir: string | null,
  dryRun: boolean,
  token: string,
): Promise<Approvable<ReloadResult>> {
  return postApprovable<ReloadResult>(
    baseUrl,
    "/config/reload",
    { config_dir: configDir, dry_run: dryRun },
    token,
  );
}

/** What promote.ts shows: `level` picks the notification, `text` is its message. */
export interface PromoteMessage {
  level: "info" | "warning" | "error";
  text: string;
}

/**
 * The pre-flight's outcome as promote.ts acts on it: the would-be graph to confirm, or an error to
 * show and stop on. The engine never holds a dry run. If one is held anyway, a pending approval now
 * exists whose release runs a REAL reload, so the error names its id for the user to have rejected.
 */
export function preflightOutcome(
  outcome: Approvable<ReloadResult>,
): { ok: true; result: ReloadResult } | { ok: false; message: PromoteMessage } {
  if (outcome.kind === "done") {
    return { ok: true, result: outcome.body };
  }
  return {
    ok: false,
    message: {
      level: "error",
      text:
        "MessageFoundry: pre-flight failed: the engine held the dry run for a second approver " +
        `(approval ${outcome.pending.approval_id}) instead of checking the config. Nothing is live ` +
        "yet, but releasing that approval would run a real reload, so have an approver reject it.",
    },
  };
}

/**
 * The message for the apply step's outcome. A held reload is a warning that names the approval id
 * and says the config is not live; it never prints graph counts, because no graph was swapped.
 * Each outcome is its own branch, so another one (a degraded apply, BACKLOG #2259) is one more case.
 */
export function promoteOutcomeMessage(
  targetName: string,
  outcome: Approvable<ReloadResult>,
): PromoteMessage {
  switch (outcome.kind) {
    case "held":
      // The engine re-reads the config directory when the approval is released, so the text does
      // not promise that the config pre-flighted here is the one that goes live.
      return {
        level: "warning",
        text:
          `MessageFoundry: the promote to ${targetName} is held for a second approver ` +
          `(approval ${outcome.pending.approval_id}). The new config is NOT live yet. It goes live ` +
          "only if a different user approves the request, and the engine then loads the config " +
          "as it is at that moment. Until then the engine keeps its current config.",
      };
    case "done": {
      const r = outcome.body;
      return {
        level: "info",
        text:
          `MessageFoundry: promoted to ${targetName} — live graph: ${r.inbound} inbound, ` +
          `${r.outbound} outbound, ${r.routers} routers, ${r.handlers} handlers` +
          `${r.running ? ", running" : ""}.`,
      };
    }
  }
}
