// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Pure (vscode-free) half of the promote flow's reload step: the `/config/reload` call and the words
// the promote shows for each outcome. Kept out of promote.ts, which imports vscode, so the node-only
// `test:unit` leg exercises it on every CI leg rather than only on the Windows integration leg
// (BACKLOG #1981). Its imports are vscode-free for the same reason.
import { approvalText, postApprovable, type Approvable } from "./engineClient";
import { isRecord } from "./engineTrustModel";

/**
 * The fields of messagefoundry/api/models.py:ReloadResult (the /config/reload response) that the
 * promote reads. The engine also sends `degraded` and `failures`; reporting those is BACKLOG #2259.
 * `restart_required` holds setting names on an applied reload, and is null on a dry run, which did
 * not check. It is `unknown` here because `isReloadResult` does not check it, so a reader has to go
 * through `reloadShortfall`.
 */
export interface ReloadResult {
  inbound: number;
  outbound: number;
  routers: number;
  handlers: number;
  running: boolean;
  dry_run: boolean;
  restart_required?: unknown;
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

/** Whether a finished reply really is a reload result, so its counts can be printed. A reply that is
 *  not (an empty body, a proxy's page) must not be announced as a promote with undefined counts. */
function isReloadResult(body: unknown): body is ReloadResult {
  return (
    isRecord(body) &&
    ["inbound", "outbound", "routers", "handlers"].every((k) => typeof body[k] === "number")
  );
}

/**
 * The pre-flight's outcome as promote.ts acts on it: the would-be graph to confirm, or an error to
 * show and stop on. The engine never holds a dry run. If one is held anyway, a pending approval now
 * exists whose release runs a REAL reload, so the error names it for the user to have rejected.
 */
export function preflightOutcome(
  outcome: Approvable<ReloadResult>,
): { ok: true; result: ReloadResult } | { ok: false; message: PromoteMessage } {
  if (outcome.kind === "held") {
    return {
      ok: false,
      message: {
        level: "error",
        text:
          "MessageFoundry: pre-flight failed: the engine held the dry run for a second approver " +
          `(${approvalText(outcome.hold.approvalId)}) instead of checking the config. Nothing is ` +
          "live yet, but releasing that approval would run a real reload, so have an approver reject it.",
      },
    };
  }
  if (!isReloadResult(outcome.body)) {
    return {
      ok: false,
      message: {
        level: "error",
        text: "MessageFoundry: pre-flight failed: the engine did not answer with a reload result.",
      },
    };
  }
  return { ok: true, result: outcome.body };
}

/**
 * One `restart_required` entry: a setting name, such as `[auth].ad_tls_ca_cert_file`. This server
 * text is headed for a notification, so a list holding anything else is reported as unreadable and
 * never printed.
 */
const SETTING_NAME_RE = /^\[[a-z0-9_]{1,64}\]\.[a-z0-9_]{1,64}$/;

/**
 * The sentences for what a live swap left to do, as far as this reply says. A list, as in the web
 * console's `_reload_shortfall`, so a degraded apply (BACKLOG #2259, not reported here yet) can sit
 * beside the restart sentence. The first entry leads the notification, so it reads on from the
 * message's prefix. This reads applied replies only, so null or no value is unreadable, as any other
 * shape is. An unreadable list keeps the counts and says so: the swap did happen, and it must not
 * read as a clean promote.
 */
function reloadShortfall(r: ReloadResult): string[] {
  const names = r.restart_required;
  if (
    !Array.isArray(names) ||
    !names.every((name) => typeof name === "string" && SETTING_NAME_RE.test(name))
  ) {
    return [
      "check the engine's log for trust anchors that take a restart: the engine's list of them " +
        "could not be read.",
    ];
  }
  if (names.length === 0) {
    return [];
  }
  return [
    `restart the engine for ${names.join(", ")}: this reload checked each changed CA file but ` +
      "does not load it, so the engine still trusts the old CA.",
    "The settings list above is not complete, for at least these reasons: it covers only the " +
      "engine that answered; another engine shard reports only once a reload reaches its own " +
      "API; a cluster node reports only in its own log, and only if it converges on the reload; " +
      'and the dialling CAs are never listed. See the section "Outbound TLS trust anchor — ' +
      'pinned internal CA" of docs/SECURITY.md in the MessageFoundry repository for which of ' +
      "those need a restart.",
  ];
}

/**
 * The message for the apply step's outcome. A held reload is a warning that names the approval and
 * says the config is not live; it never prints graph counts, because no graph was swapped. A live
 * swap with a shortfall is a warning too, and it leads with the shortfall: VS Code starts a
 * notification with no button collapsed to one clipped line, so the words to act on come first, in
 * as few characters as they can. Held, invalid and live exclude each other, so each is its own
 * branch.
 */
export function promoteOutcomeMessage(
  targetName: string,
  outcome: Approvable<ReloadResult>,
): PromoteMessage {
  if (outcome.kind === "held") {
    // The engine re-reads the config directory when the approval is released, so the text does not
    // promise that the config pre-flighted here is the one that goes live.
    return {
      level: "warning",
      text:
        `MessageFoundry: the promote to ${targetName} is held for a second approver ` +
        `(${approvalText(outcome.hold.approvalId)}). The new config is NOT live yet. It goes live ` +
        "only if a different user approves the request, and the engine then loads the config " +
        "as it is at that moment. Until then the engine keeps its current config.",
    };
  }
  const r = outcome.body;
  if (!isReloadResult(r)) {
    return {
      level: "error",
      text:
        `MessageFoundry: the engine at ${targetName} did not answer the promote with a reload ` +
        "result, so it is unknown whether the new config is live. Check the engine before retrying.",
    };
  }
  const graph =
    `to ${targetName} — live graph: ${r.inbound} inbound, ${r.outbound} outbound, ` +
    `${r.routers} routers, ${r.handlers} handlers${r.running ? ", running" : ""}.`;
  const [lead, ...rest] = reloadShortfall(r);
  if (lead === undefined) {
    return { level: "info", text: `MessageFoundry: promoted ${graph}` };
  }
  return {
    level: "warning",
    text: [`MessageFoundry: ${lead}`, `Promoted ${graph}`, ...rest].join(" "),
  };
}
