// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Organization and contributors
// Live per-element decorations for the CONNECTIONS view (ADR 0091 "live decorations"): an opt-in
// (`messagefoundry.liveStatus.enabled`, default OFF) poll of the engine's `GET /connections`
// (Permission.MONITORING_READ) that feeds status + message counts onto inbound/outbound rows via
// GraphProvider.setRuntime. It never prompts and never toasts: 401/403/unreachable all degrade to
// "no live data" (undecorated rows), because a background timer must not interrupt anyone. The row
// aggregation is the pure liveStatusModel; this is the Extension-Host shell.
//
// TWO THINGS HERE ARE LOAD-BEARING AND EASY TO "TIDY" INTO BUGS:
//   1. The poll sends NO TOKEN — the same rule statusBar.ts states as its item 1, for the same
//      reason. `GET /connections` is gated by plain `require(Permission.MONITORING_READ)`, and
//      `require()` resolves the bearer with `identity_for_token(bearer_token(request))` — the
//      default `activity=True`, which refreshes the session's idle clock. So a bearer on
//      this timer would refresh the session's idle clock on every tick and make the engine's
//      30-minute idle timeout unreachable while a VS Code window is open (CWE-613). No client-side
//      opt-out exists: nothing in the engine API reads a header, query parameter, or route that lets
//      a caller ask for `activity=False` — that flag is a server-side per-route decision only. This
//      file DID send a bearer here, which is the defect this block exists to stop coming back. The
//      tokenlessness is DATA (`LIVE_STATUS_PLAN`, asserted in CI), not this comment. Read against
//      the engine source, not a running engine: the claim rests on `identity_for_token`'s signature
//      and the route's dependency chain.
//   2. What that costs, accepted on purpose. Against an engine with auth ENABLED the poll gets a 401
//      and the rows stay undecorated, so decorations now appear only where `/connections` answers
//      tokenless — a dev or embedded engine run with `allow_no_auth`. The setting ships OFF by
//      default, so no one who has not asked for it loses anything; what is given up is a status word
//      and a count on a tree row, and what is kept is an automatic-logoff control on the one client
//      that stays open all day. The full monitor is the web console at /ui, which reads the same
//      data under `activity=False` and is the surface built for it. Making a bearer safe instead
//      needs an engine-side passive-read surface, which is its own change, not a tidy-up here.
import * as vscode from "vscode";
import { peekToken } from "./auth";
import { engineUrl, environments } from "./cli";
import { getJson } from "./engineClient";
import { resolveEngineStatusTarget } from "./engineStatusModel";
import { assertTargetAllowed } from "./engineTarget";
import type { GraphProvider } from "./graphTree";
import { buildRuntimeMap, LIVE_STATUS_PLAN, type ConnectionRowLite } from "./liveStatusModel";
import type { RuntimeMap } from "./graphModel";

/** Floor for the poll interval (seconds) — the settings schema declares the same minimum; this
 *  clamp also catches a hand-edited settings.json value below it. */
const MIN_INTERVAL_SECONDS = 5;

function readSettings(): { enabled: boolean; intervalMs: number } {
  const c = vscode.workspace.getConfiguration("messagefoundry");
  const seconds = c.get<number>("liveStatus.intervalSeconds", 10);
  const clamped = Math.max(
    MIN_INTERVAL_SECONDS,
    typeof seconds === "number" && Number.isFinite(seconds) ? seconds : 10,
  );
  return { enabled: c.get<boolean>("liveStatus.enabled", false), intervalMs: clamped * 1000 };
}

/**
 * Owns the poll timer and pushes each cycle's RuntimeMap (or undefined = degrade) into the graph
 * provider. Same lifecycle discipline as EngineStatusBar: an in-flight guard so a slow engine
 * can't stack overlapping requests, and a run token so a settings change mid-poll drops the stale
 * result instead of applying it under the new target.
 */
export class LiveStatusPoller implements vscode.Disposable {
  private timer: ReturnType<typeof setInterval> | undefined;
  private polling = false;
  private runToken = 0;

  constructor(
    private readonly ctx: vscode.ExtensionContext,
    private readonly graph: GraphProvider,
  ) {}

  /** (Re)apply the liveStatus settings: start/stop/re-pace the timer; when disabled, drop any
   *  decorations already shown so the tree honestly reflects "not polling". */
  applySettings(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = undefined;
    }
    this.runToken++; // a poll in flight for the old settings/target must not land
    const { enabled, intervalMs } = readSettings();
    if (!enabled) {
      this.graph.setRuntime(undefined);
      return;
    }
    void this.poll();
    this.timer = setInterval(() => void this.poll(), intervalMs);
  }

  /** One poll cycle. Every failure path degrades silently to "no live data" — a background timer
   *  must never surface an error toast loop (the status bar already tells the user the engine is
   *  down; a missing/expired session is a normal state, not an error). */
  async poll(): Promise<void> {
    if (this.polling) {
      return; // previous cycle still in flight — don't pile up
    }
    this.polling = true;
    const token = ++this.runToken;
    let map: RuntimeMap | undefined;
    try {
      // Same target the engine status bar reflects (first named environment, else engineUrl).
      const url = resolveEngineStatusTarget(engineUrl(), environments()).url;
      // The SEC-005 host gate (ADR 0035). Kept even though the poll is now tokenless: it is about
      // the TARGET, and a background timer should not reach an arbitrary non-loopback plaintext host
      // either. It is also the guard that would still hold if LIVE_STATUS_PLAN ever gained a bearer.
      if (assertTargetAllowed(url).ok) {
        const entry = LIVE_STATUS_PLAN[0];
        // The bearer is attached IFF the plan says so — which is what makes `authenticated: false`
        // an actual control rather than a comment (same shape as statusBar.runProbe). No entry says
        // so today, so the token is never even read and the request carries no Authorization header.
        const bearer = entry.authenticated ? await peekToken(this.ctx, url) : undefined;
        try {
          const rows = await getJson<ConnectionRowLite[]>(url, entry.route, bearer);
          map = Array.isArray(rows) ? buildRuntimeMap(rows) : undefined;
        } catch {
          // Unauthorized / unreachable / non-JSON → undecorated rows, silently. Nothing is cleared
          // here: the poll sends no bearer, so a 401 is the engine saying "this route needs auth",
          // NOT evidence that the cached session died. Clearing on it would sign the user out from a
          // timer over a request their session never took part in. `auth.withAuth` still clears on a
          // 401 from a request that DID carry the token — the only place that inference is sound.
          map = undefined;
        }
      }
    } finally {
      this.polling = false;
    }
    if (token !== this.runToken) {
      return; // superseded (settings changed mid-poll)
    }
    this.graph.setRuntime(map);
  }

  dispose(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = undefined;
    }
  }
}

/** Wire the poller: apply current settings now, and re-apply whenever the liveStatus settings or
 *  the engine target (engineUrl/environments, which also moves the token's SecretStorage key)
 *  change. All disposables ride context.subscriptions. */
export function registerLiveStatus(
  context: vscode.ExtensionContext,
  graph: GraphProvider,
): LiveStatusPoller {
  const poller = new LiveStatusPoller(context, graph);
  poller.applySettings();
  context.subscriptions.push(
    poller,
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (
        e.affectsConfiguration("messagefoundry.liveStatus") ||
        e.affectsConfiguration("messagefoundry.engineUrl") ||
        e.affectsConfiguration("messagefoundry.environments")
      ) {
        poller.applySettings();
      }
    }),
  );
  return poller;
}
