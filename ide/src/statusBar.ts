// Engine status-bar item (#221c): a right-aligned indicator of the promote target (URL / environment)
// and its reachability, polled over HTTP via the existing engineClient. It is DISTINCT from
// liveDebug.ts's left-side "MEFOR Live" / "Values" toggles — those are about the offline dry-run loop;
// this reflects the real, running engine the analyst would promote to. Clicking it opens engine
// actions (reveal the MessageFoundry panel / open the URL / configure the target). All display logic
// lives in the vscode-free engineStatusModel (unit-tested node-side); this is the Extension-Host shell.
import * as vscode from "vscode";
import { engineUrl, environments } from "./cli";
import { HttpError, getJson } from "./engineClient";
import {
  classifyProbe,
  formatEngineStatus,
  resolveEngineStatusTarget,
  type EngineStatusTarget,
  type ProbeOutcome,
  type Reachability,
} from "./engineStatusModel";

/** How often (ms) to re-probe the engine. Modest — this is a liveness hint, not a monitor (that's the Console). */
const POLL_INTERVAL_MS = 15_000;

/** The injectable probe seam. The real one hits the tokenless `GET /health`; tests pass a canned outcome. */
export type EngineProbe = (url: string) => Promise<ProbeOutcome>;

/** Production probe: any HTTP answer (even a non-2xx) means the engine is up; only a transport failure
 *  (connection refused / DNS / reset) is unreachable. `/health` is tokenless (api/app.py). */
export const httpProbe: EngineProbe = async (url) => {
  try {
    await getJson(url, "/health");
    return { kind: "ok" };
  } catch (e) {
    if (e instanceof HttpError) {
      return { kind: "httpError", status: e.status };
    }
    return { kind: "networkError" };
  }
};

/**
 * Owns the status-bar item, the current target/reachability, and the poll timer. The probe is injected
 * so the controller is drivable in a test without a live engine; the rendering it performs is the pure
 * {@link formatEngineStatus}.
 */
export class EngineStatusBar implements vscode.Disposable {
  private readonly item: vscode.StatusBarItem;
  private timer: ReturnType<typeof setInterval> | undefined;
  private target: EngineStatusTarget;
  private reachability: Reachability = "unknown";
  private runToken = 0;
  private probing = false;

  constructor(private readonly probe: EngineProbe = httpProbe) {
    this.item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    this.item.command = "messagefoundry.engineStatusClicked";
    this.target = this.resolveTarget();
    this.render();
    this.item.show();
  }

  private resolveTarget(): EngineStatusTarget {
    return resolveEngineStatusTarget(engineUrl(), environments());
  }

  private render(): void {
    const { text, tooltip } = formatEngineStatus(this.target, this.reachability);
    this.item.text = text;
    this.item.tooltip = tooltip;
    this.item.backgroundColor =
      this.reachability === "unreachable"
        ? new vscode.ThemeColor("statusBarItem.warningBackground")
        : undefined;
  }

  /** Re-read the target from settings (e.g. after the user edits engineUrl/environments) and re-probe. */
  refreshTarget(): void {
    this.target = this.resolveTarget();
    // Invalidate any probe still in flight for the OLD target: bumping the token makes its result be
    // dropped even if the immediate poll() below is skipped by the in-flight guard (else the stale
    // old-URL outcome would be applied under the new target's label; the next tick re-probes the new one).
    this.runToken++;
    this.reachability = "unknown";
    this.render();
    void this.poll();
  }

  /** One probe cycle: classify the outcome, then render. A per-cycle token drops a stale result if the
   *  target changed mid-probe. An in-flight guard skips the cycle if the previous probe hasn't settled,
   *  so a hung/slow engine can't stack overlapping probes across the poll interval (the probe itself is
   *  bounded by getJson's timeout, so `probing` always clears — this is the belt-and-suspenders). */
  async poll(): Promise<void> {
    if (this.probing) {
      return; // previous probe still in flight — don't pile up
    }
    this.probing = true;
    const token = ++this.runToken;
    const url = this.target.url;
    let outcome: ProbeOutcome;
    try {
      outcome = await this.probe(url);
    } catch {
      outcome = { kind: "networkError" };
    } finally {
      this.probing = false;
    }
    if (token !== this.runToken) {
      return; // superseded (the target changed mid-probe)
    }
    this.reachability = classifyProbe(outcome);
    this.render();
  }

  /** Start periodic polling (and probe once immediately). Idempotent. */
  start(): void {
    if (this.timer) {
      return;
    }
    void this.poll();
    this.timer = setInterval(() => void this.poll(), POLL_INTERVAL_MS);
  }

  /** The URL the item currently reflects (for the click-through "open engine URL" action). */
  currentUrl(): string {
    return this.target.url;
  }

  dispose(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = undefined;
    }
    this.item.dispose();
  }
}

/**
 * Wire the engine status bar: create the controller, register its click command (a small action menu),
 * start polling, and re-resolve the target whenever the engine settings change. Returns the controller.
 */
export function registerEngineStatusBar(context: vscode.ExtensionContext): EngineStatusBar {
  const bar = new EngineStatusBar();
  context.subscriptions.push(
    bar,
    vscode.commands.registerCommand("messagefoundry.engineStatusClicked", async () => {
      const pick = await vscode.window.showQuickPick(
        [
          { label: "$(window) Open MessageFoundry panel", action: "panel" as const },
          { label: "$(link-external) Open engine URL in browser", action: "browser" as const },
          { label: "$(gear) Configure engine target…", action: "settings" as const },
        ],
        { placeHolder: `Engine: ${bar.currentUrl()}` },
      );
      if (!pick) {
        return;
      }
      if (pick.action === "panel") {
        void vscode.commands.executeCommand("workbench.view.extension.messagefoundry");
      } else if (pick.action === "browser") {
        void vscode.env.openExternal(vscode.Uri.parse(bar.currentUrl()));
      } else {
        void vscode.commands.executeCommand("workbench.action.openSettings", "messagefoundry.engineUrl");
      }
    }),
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (
        e.affectsConfiguration("messagefoundry.engineUrl") ||
        e.affectsConfiguration("messagefoundry.environments")
      ) {
        bar.refreshTarget();
      }
    }),
  );
  bar.start();
  return bar;
}
