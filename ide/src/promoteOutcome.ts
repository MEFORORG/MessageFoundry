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
 * promote reads. `degraded` is true when the graph swapped and a follow-on step did not complete,
 * and `failures` then names each step (BACKLOG #2259, #5836). `restart_required` holds setting names
 * on an applied reload, and is null on a dry run, which did not check. The three are `unknown` here
 * because `isReloadResult` does not check them, so a reader has to go through `reloadShortfall`.
 */
export interface ReloadResult {
  inbound: number;
  outbound: number;
  routers: number;
  handlers: number;
  running: boolean;
  dry_run: boolean;
  degraded?: unknown;
  failures?: unknown;
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
 * One `failures` entry: a follow-on step label, such as `reference_sync` (ReloadResult's docstring
 * in messagefoundry/api/models.py lists them). Server text headed for a notification, so a list
 * holding anything else is reported as unreadable and never printed, as with `SETTING_NAME_RE`.
 */
const STEP_LABEL_RE = /^[a-z0-9_]{1,64}$/;

/** `value` as a list of server strings each matching `re`, or undefined for any other shape. The
 *  one gate on server text bound for a notification, so each list is checked the same way. */
function printableList(value: unknown, re: RegExp): string[] | undefined {
  return Array.isArray(value) && value.every((v) => typeof v === "string" && re.test(v))
    ? (value as string[])
    : undefined;
}

/** The degraded sentence, or none for a reload whose follow-on steps all completed. The engine
 *  sends `degraded` and `failures` on every reply, and the two agree, so any other pairing (a
 *  missing or non-boolean `degraded`, a clean reply naming a step, a degraded one naming none) is
 *  unreadable, not clean. */
function degradedShortfall(r: ReloadResult): string[] {
  const steps = printableList(r.failures, STEP_LABEL_RE);
  if (r.degraded === false && steps?.length === 0) {
    return [];
  }
  if (r.degraded !== true || steps === undefined || steps.length === 0) {
    return [
      "Check the engine's log for whether a follow-on step failed after the swap: the engine's " +
        "report of them could not be read.",
    ];
  }
  // `audit` is among the labels, and nobody can redo that one by hand, so the sentence names the
  // steps and the log rather than promising a step to finish.
  const which = steps.length === 1 ? "this follow-on step" : "these follow-on steps";
  return [
    `Check the engine's log: ${which} failed after the swap: ${steps.join(", ")}. ` +
      "The new graph is live.",
  ];
}

/**
 * The sentences for what a live swap left to do, as far as this reply says. A list, as in the web
 * console's `_reload_shortfall`, so a degraded apply (BACKLOG #2259, #5836) sits beside the restart
 * sentence. A known restart goes first, unlike the web console, which shows each sentence as its own
 * banner: here only the lead survives a collapsed notification, and a stale CA is the one left
 * trusted. An unreadable restart list knows of no stale CA, so a degraded report leads then. This
 * reads applied replies only, so null or no value is unreadable, as any other shape
 * is. An unreadable list keeps the counts and says so: the swap did happen, and it must not read as
 * a clean promote.
 */
function reloadShortfall(r: ReloadResult): string[] {
  const restart = restartShortfall(r);
  const degraded = degradedShortfall(r);
  return printableList(r.restart_required, SETTING_NAME_RE) === undefined
    ? [...degraded, ...restart]
    : [...restart, ...degraded];
}

function restartShortfall(r: ReloadResult): string[] {
  const names = printableList(r.restart_required, SETTING_NAME_RE);
  if (names === undefined) {
    return [
      "Check the engine's log for trust anchors that take a restart: the engine's list of them " +
        "could not be read.",
    ];
  }
  if (names.length === 0) {
    return [];
  }
  return [
    `Restart the engine for ${names.join(", ")}: this reload checked each changed CA file but ` +
      "does not load it, so the engine still trusts the old CA.",
    'The settings list above is not complete: see the section "Outbound TLS trust anchor" of ' +
      "docs/SECURITY.md in the MessageFoundry repository, at the paragraph " +
      '"What a reload\'s restart_required list covers".',
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
    // The lead reads on from the prefix, so only it starts lower-case.
    text: [
      `MessageFoundry: ${lead.charAt(0).toLowerCase()}${lead.slice(1)}`,
      `Promoted ${graph}`,
      ...rest,
    ].join(" "),
  };
}
