// Live per-element decorations for the CONNECTIONS view (ADR 0091 "live decorations"): an opt-in
// (`messagefoundry.liveStatus.enabled`, default OFF) poll of the engine's `GET /connections`
// (Permission.MONITORING_READ) that feeds status + message counts onto inbound/outbound rows via
// GraphProvider.setRuntime. Deliberately PASSIVE about auth: it reuses the session Stage → Promote
// cached in SecretStorage (auth.peekToken — never prompts), and treats 401/403/unreachable as
// "no live data" (undecorated rows), never a toast or a login popup from a background timer. A dev
// engine embedded with allow_no_auth serves /connections tokenless, so the local loop needs no
// sign-in at all. The row aggregation is the pure liveStatusModel; this is the Extension-Host shell.
import * as vscode from "vscode";
import { clearToken, peekToken } from "./auth";
import { engineUrl, environments } from "./cli";
import { getJson, HttpError } from "./engineClient";
import { resolveEngineStatusTarget } from "./engineStatusModel";
import { assertTargetAllowed } from "./engineTarget";
import type { GraphProvider } from "./graphTree";
import { buildRuntimeMap, type ConnectionRowLite } from "./liveStatusModel";
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
      // SEC-005: never send a bearer token in clear to a non-loopback http:// host.
      if (assertTargetAllowed(url).ok) {
        const bearer = await peekToken(this.ctx, url);
        try {
          const rows = await getJson<ConnectionRowLite[]>(url, "/connections", bearer);
          map = Array.isArray(rows) ? buildRuntimeMap(rows) : undefined;
        } catch (e) {
          if (e instanceof HttpError && e.status === 401 && bearer) {
            // The cached session is dead — clear it so the next interactive action (promote)
            // re-authenticates cleanly. A 403 is NOT cleared: the session is valid, the account
            // just lacks MONITORING_READ; clearing would only churn the promote sign-in.
            await clearToken(this.ctx, url);
          }
          map = undefined; // unauthorized / unreachable / non-JSON → undecorated rows, silently
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
