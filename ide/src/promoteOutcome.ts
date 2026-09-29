// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Pure (vscode-free) half of the promote flow's reload step: the `/config/reload` call and the words
// the promote shows for each outcome. Kept out of promote.ts, which imports vscode, so the node-only
// `test:unit` leg exercises it on every CI leg rather than only on the Windows integration leg
// (BACKLOG #1981). It imports only engineClient.ts, which is vscode-free for the same reason.
import { postApprovable, type Approvable } from "./engineClient";

/** Mirrors messagefoundry/api/models.py:ReloadResult (the /config/reload response). */
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
  level: "info" | "warning";
  text: string;
}

/**
 * The message for the apply step's outcome. A held reload is a warning that names the approval id
 * and says the config is not live; it never prints graph counts, because no graph was swapped.
 * Each outcome is its own branch, so a later one (a degraded apply, say) is one more case here.
 */
export function promoteOutcomeMessage(
  targetName: string,
  outcome: Approvable<ReloadResult>,
): PromoteMessage {
  switch (outcome.kind) {
    case "held":
      return {
        level: "warning",
        text:
          `MessageFoundry: the promote to ${targetName} is held for a second approver ` +
          `(approval ${outcome.pending.approval_id}). The new config is NOT live yet. It goes live ` +
          `only if a different user approves the request; until then the engine keeps its current config.`,
      };
    case "done": {
      const r = outcome.body;
      return {
        level: "info",
        text:
          `MessageFoundry: promoted to ${targetName} — live graph: ${r.inbound} inbound, ` +
          `${r.outbound} outbound, ${r.routers} routers, ${r.handlers} handlers` +
          `${r.running ? " • running" : ""}.`,
      };
    }
  }
}

/** Shown if the engine holds the dry-run pre-flight, which it never should: nothing was checked. */
export const PREFLIGHT_HELD_MESSAGE =
  "MessageFoundry: pre-flight failed: the engine held the dry run for approval instead of " +
  "checking the config. Nothing was promoted.";
