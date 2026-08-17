// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Organization and contributors
// The extension's engine log (ADR — engine-link doctor). Until now NOTHING on the engine path logged
// anywhere: a refused socket, a 5s timeout, a 401 and a cleared token all vanished without a trace the
// user could read. "Let me SEE the connection to the engine" is answered largely by this file.
//
// WHAT MAY BE LOGGED — and this is a hard rule, not a style preference (CLAUDE.md §9):
//   URLs, routes, HTTP status codes, transport error codes, durations, and our own verdict.
// WHAT MAY NEVER BE LOGGED:
//   a response BODY, a bearer TOKEN, an Authorization header, or a username/password.
// A user pastes this channel into a bug report. FastAPI's `detail` string is deliberately NOT logged
// verbatim for that reason — we log our own classified verdict instead, which is derived from it and
// carries no server-supplied text. This is also why the log is wired at the status-bar layer and NOT
// inside the shared engineClient: there, it would silently capture whatever every future caller sends.
import * as vscode from "vscode";

import { PROBE_ENDPOINTS, type EngineLink, type ProbeOutcome } from "./engineStatusModel";

let channel: vscode.LogOutputChannel | undefined;

/** The singleton channel. Created lazily so merely importing this module costs nothing. */
export function engineLog(): vscode.LogOutputChannel {
  if (!channel) {
    channel = vscode.window.createOutputChannel("MessageFoundry Engine", { log: true });
  }
  return channel;
}

export function disposeEngineLog(): void {
  channel?.dispose();
  channel = undefined;
}

/** Reveal the channel (the "Show the engine log" action). */
export function showEngineLog(): void {
  engineLog().show(true);
}

/** One line per probe: what we asked, what came back, how long it took, and what we concluded.
 *
 *  `route` is asserted against the frozen {@link PROBE_ENDPOINTS} allowlist — a probe of `/messages` or
 *  `/connections` is not merely discouraged here, it cannot be logged, because it must not happen. */
export function logProbe(
  url: string,
  route: string,
  outcome: ProbeOutcome,
  elapsedMs: number,
  verdict: string,
): void {
  const log = engineLog();
  if (!(PROBE_ENDPOINTS as readonly string[]).includes(route)) {
    // Loud, because this means someone widened the probe surface past the boundary the ADR froze.
    log.error(`probe route ${route} is not in the allowed probe set — refusing to log it`);
    return;
  }
  const ms = Math.round(elapsedMs);
  switch (outcome.kind) {
    case "ok":
      log.info(`GET ${url}${route} → 200 (${ms}ms) — ${verdict}`);
      return;
    case "httpError":
      // The status code, never the body. A 403's `detail` becomes our verdict, not a logged string.
      log.warn(`GET ${url}${route} → HTTP ${outcome.status} (${ms}ms) — ${verdict}`);
      return;
    case "networkError":
      log.warn(`GET ${url}${route} → ${outcome.code ?? "transport failure"} (${ms}ms) — ${verdict}`);
      return;
  }
}

/**
 * One line per state transition, so the log reads as a story rather than a wall of probes.
 *
 * It logs the STATE and our own classification — never `link.reason`. That was a real leak: `classifyDeep`
 * sets `reason` to the engine's FastAPI `detail` string verbatim, and for a non-JSON error body
 * engineClient folds the RAW BODY into the message. Writing that here would put server-supplied text —
 * unbounded, and from a host that may not even be our engine (that is what `foreign` means) — into a
 * channel users paste into bug reports. `blocked` is the one case where the *reason* matters, and its
 * sub-classification (`mustChangePassword` / `permission` / …) is OURS, so it is safe and sufficient.
 */
export function logState(previous: EngineLink | undefined, next: EngineLink): void {
  if (previous?.state === next.state) {
    return;
  }
  const why = next.blocked ?? next.code; // both are OUR vocabulary, never the server's text
  engineLog().info(
    `engine link: ${previous?.state ?? "unknown"} → ${next.state}${why ? ` (${why})` : ""}`,
  );
}

/** One line per user-invoked action, so "I clicked sign in and nothing happened" is answerable. */
export function logAction(action: string, detail?: string): void {
  engineLog().info(`action: ${action}${detail ? ` — ${detail}` : ""}`);
}
