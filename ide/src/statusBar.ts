// Engine status-bar item — the Extension-Host shell for the engine-link doctor (ADR — engine-link
// doctor). It is DISTINCT from liveDebug.ts's left-side "MEFOR Live" / "Values" toggles (those are the
// offline dry-run loop); this reflects the real, running engine the analyst promotes to.
//
// All display/classification logic lives in the vscode-free engineStatusModel (unit-tested node-side).
// This file is only the parts that need `vscode`: the item, the timer, the HTTP calls, and the menu.
//
// THREE THINGS HERE ARE LOAD-BEARING AND EASY TO "TIDY" INTO BUGS:
//   1. The poll sends NO TOKEN. Not an oversight — a bearer on a 15s timer would keep refreshing the
//      engine's session idle clock (`identity_for_token(..., activity=True)`) and make its 30-minute
//      idle timeout unreachable forever (CWE-613). The timer may only ever prove the negative.
//   2. `verify()` is USER-INITIATED ONLY (click / activation / after promote). It is the only thing
//      that may produce a green check, because only a non-must-change-exempt PROTECTED route can prove
//      a session actually works — /health and /auth/me both answer 200 for a locked-out user.
//   3. The click handler's only permitted body is `executeCommand(action.command, ...)`. The model
//      hands out command IDs, never data, so no engine workload can reach this surface (the IDE
//      renders and repairs the LINK; the Console renders the workload).
import { execFile } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";

import * as vscode from "vscode";

import { peekToken, signIn, signOut } from "./auth";
import { configDir, engineUrl, environments, pythonPath, serviceConfig, workspaceDir } from "./cli";
import {
  buildBootstrapPlan,
  buildServeInvocation,
  classifyPreflight,
  preflightArgs,
  runDirHasEngine,
  type PreflightVerdict,
} from "./engineControlModel";
import { HttpError, NetworkError, getJson } from "./engineClient";
import { logAction, logProbe, logState, showEngineLog } from "./engineLog";
import { assertTargetAllowed, isLocalEngine } from "./engineTarget";
import {
  CMD,
  ENVIRONMENT_PLAN,
  POLL_PLAN,
  VERIFY_PLAN,
  classifyDeep,
  classifyHealth,
  formatEngineStatus,
  planActions,
  readVersion,
  resolveEngineStatusTarget,
  withStaleness,
  type EngineAction,
  type EngineControlContext,
  type EngineLink,
  type EngineStatusTarget,
  type ProbeOutcome,
  type ProbePlanEntry,
} from "./engineStatusModel";

/** How often (ms) to re-probe. Modest — this is a liveness hint, not a monitor (that's the Console). */
const POLL_INTERVAL_MS = 15_000;

/** A probe the user is waiting on must feel like it did something, but one that resolves in 30ms must not
 *  flash. Hold the spinner at least this long once shown. */
const MIN_SPINNER_MS = 250;

/** Shorter than engineClient's 5s default: a click waits on these, and serial 5s timeouts would leave the
 *  user staring at a spinner. A hung engine is diagnosed, not waited on. */
const PROBE_TIMEOUT_MS = 2500;

/** A click re-probes only if the last check is older than this. The timer already keeps the link fresh, so
 *  in the common case the menu opens INSTANTLY — clicking a status bar item should not cost an HTTP
 *  round-trip you are made to watch. (Only a stale/unknown link makes the click wait.) */
const CLICK_FRESH_MS = 5_000;

/** The injectable HTTP seam. Tests drive the controller with canned outcomes; production calls the engine. */
export type EngineFetch = (
  url: string,
  route: string,
  token: string | undefined,
  timeoutMs: number,
) => Promise<ProbeOutcome>;

/**
 * The production fetch: turn engineClient's exceptions back into evidence. Every branch preserves what
 * the old probe threw away — the parsed body, the status code, and the transport errno — because those
 * three things are the entire difference between "unreachable" and a diagnosis the user can act on.
 */
export const httpFetch: EngineFetch = async (url, route, token, timeoutMs) => {
  try {
    const body = await getJson<unknown>(url, route, token, timeoutMs);
    return { kind: "ok", body };
  } catch (e) {
    if (e instanceof HttpError) {
      return { kind: "httpError", status: e.status, detail: e.message };
    }
    if (e instanceof NetworkError) {
      return { kind: "networkError", code: e.code };
    }
    return { kind: "networkError" };
  }
};

/**
 * Owns the status-bar item, the link state, and the poll timer. The fetch is injected so the controller
 * is drivable in a test without a live engine; every rendering decision it makes is the pure
 * {@link formatEngineStatus} / {@link planActions}.
 */
export class EngineStatusBar implements vscode.Disposable {
  private readonly item: vscode.StatusBarItem;
  private timer: ReturnType<typeof setInterval> | undefined;
  private link: EngineLink;
  /** Bumped ONLY when the target changes. A probe captures it and drops its own result if it moved.
   *  It is deliberately NOT a per-probe counter: poll() and verify() used to share one, so a routine
   *  15s tick landing mid-verify made the deep probe think it had been superseded and discard the only
   *  verdict that can paint the item green. */
  private targetGen = 0;
  private probing = false;
  private verifying = false;
  private busy = false;
  /** A settings change that arrives while a probe is in flight, replayed once it lands. */
  private pendingTargetRefresh = false;
  /** The terminal running the engine THIS IDE started, if any. Its liveness (`exitStatus === undefined`)
   *  is the only thing that authorizes Stop/Restart — we never kill an engine we did not launch, which
   *  with parallel worktrees would risk downing another session's engine on the same port. */
  private engineTerminal: vscode.Terminal | undefined;
  private readonly termWatch: vscode.Disposable;
  /** Set once dispose() has run, so a scheduled re-probe (see scheduleProbes) that fires during extension
   *  teardown does not render onto an already-disposed status-bar item. */
  private disposed = false;
  /** Reentrancy guard for startEngine: its confirm/preflight awaits leave a window before the terminal
   *  exists, in which a second invocation (double-click, palette, hover link) would launch a 2nd engine. */
  private starting = false;

  constructor(
    private readonly ctx: vscode.ExtensionContext,
    private readonly fetch: EngineFetch = httpFetch,
  ) {
    this.item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    this.item.command = "messagefoundry.engineStatusClicked";
    this.item.name = "MessageFoundry Engine"; // names the entry in the status-bar visibility menu
    this.link = { state: "unknown", target: this.resolveTarget() };
    this.render();
    this.item.show();
    // Forget the engine terminal the moment it closes — the user closed the panel, or `serve` exited — and
    // re-probe so the item reflects reality rather than a process that is already gone.
    this.termWatch = vscode.window.onDidCloseTerminal((t) => {
      if (t === this.engineTerminal) {
        this.engineTerminal = undefined;
        void this.recheck();
      }
    });
  }

  private resolveTarget(): EngineStatusTarget {
    return resolveEngineStatusTarget(engineUrl(), environments());
  }

  /** The URL the item currently reflects (the click-through actions target it). */
  currentUrl(): string {
    return this.link.target.url;
  }

  /** The current link — for the menu and for tests. Staleness is applied so a stale green never leaks. */
  currentLink(): EngineLink {
    return withStaleness(this.link, Date.now());
  }

  private render(): void {
    if (this.busy) {
      // Feedback AT the click site. The quick-input widget opens at the top-center of the window, a
      // long way from the item the user just clicked in the corner; this is the only response that
      // appears where their eyes and their mouse actually are.
      this.item.text = "$(sync~spin) MEFOR: checking…";
      this.item.tooltip = "Checking the engine…";
      this.item.backgroundColor = undefined;
      return;
    }
    const { text, tooltipMarkdown, background } = formatEngineStatus(this.link, Date.now());
    this.item.text = text;
    this.item.tooltip = this.buildTooltip(tooltipMarkdown);
    this.item.backgroundColor =
      background === "error"
        ? new vscode.ThemeColor("statusBarItem.errorBackground")
        : background === "warning"
          ? new vscode.ThemeColor("statusBarItem.warningBackground")
          : undefined;
  }

  /**
   * The hover: the PRIMARY diagnosis surface. It renders at the item, under a cursor that is already
   * there, and needs no command dispatch at all — so it works even for a user who never realises the
   * click opens anything. The action links are a bonus, not the mechanism: every action is also in the
   * QuickPick, so if a `command:` link in a status-bar tooltip proves unreliable, nothing is lost.
   */
  private buildTooltip(markdown: string): vscode.MarkdownString {
    const actions = planActions(this.link, Date.now(), this.controlContext());
    const links = actions
      .slice(0, 3)
      .map((a) => `[${stripIcon(a.label)}](${commandUri(a)})`)
      .join(" · ");
    const md = new vscode.MarkdownString(links ? `${markdown}\n\n${links}` : markdown, true);
    // The allow-list form, never a blanket `isTrusted = true`: only these command ids may be invoked
    // from the hover, so a later markdown change cannot turn the tooltip into an arbitrary-command sink.
    md.isTrusted = { enabledCommands: Object.values(CMD) };
    return md;
  }

  /** Re-read the target from settings (the user edited engineUrl/environments) and re-probe. */
  refreshTarget(): void {
    const target = this.resolveTarget();
    if (sameTarget(target, this.link.target)) {
      return;
    }
    if (this.probing || this.verifying || this.busy) {
      // A probe is mid-flight; applying a new target now would let its result land under the new label.
      // Replay the refresh when it settles rather than dropping it on the floor (the item would otherwise
      // sit on the OLD engine until the next 15s tick).
      this.pendingTargetRefresh = true;
      return;
    }
    this.targetGen++; // any in-flight result for the old target is now void
    this.link = { state: "unknown", target };
    this.render();
    void this.recheck();
  }

  /** Run one planned probe. The bearer is attached IFF the plan says so — which is what makes
   *  {@link POLL_PLAN}'s `authenticated: false` an actual control rather than a comment. */
  private async runProbe(
    entry: ProbePlanEntry,
    url: string,
    timeoutMs: number,
  ): Promise<{ outcome: ProbeOutcome; ms: number }> {
    const token = entry.authenticated ? await peekToken(this.ctx, url) : undefined;
    const started = Date.now();
    let outcome: ProbeOutcome;
    try {
      outcome = await this.fetch(url, entry.route, token, timeoutMs);
    } catch {
      outcome = { kind: "networkError" };
    }
    return { outcome, ms: Date.now() - started };
  }

  /**
   * One TOKENLESS probe cycle (the timer's only job). It can prove the negative — down, foreign, signed
   * out — but it can never conclude "ok"; only {@link verify} can. Sending a token here would defeat the
   * engine's idle-session timeout (see the file header), which is why the bearer is driven by
   * {@link POLL_PLAN} data that CI asserts.
   */
  async poll(): Promise<void> {
    if (this.probing || this.verifying) {
      return; // don't pile up, and never clobber a deep probe the user is waiting on
    }
    this.probing = true;
    const gen = this.targetGen;
    const target = this.link.target;
    // A SecretStorage read, not a wire call: it sends no bearer, so the idle clock is untouched. Without
    // it a tokenless /health (which NEVER discloses a version to us under auth) reads as "signed out" and
    // wipes the verdict the deep probe just earned — the item would go green, then lie 15 seconds later.
    const hasSession = (await peekToken(this.ctx, target.url)) !== undefined;
    let res: { outcome: ProbeOutcome; ms: number };
    try {
      res = await this.runProbe(POLL_PLAN[0], target.url, PROBE_TIMEOUT_MS);
    } finally {
      this.probing = false;
    }
    if (gen !== this.targetGen) {
      return; // superseded (the target changed mid-probe)
    }
    const next = classifyHealth(res.outcome, target, Date.now(), hasSession);
    // Keep a verdict the deep probe EARNED: a tokenless probe cannot see our session, so it says
    // "unverified" while we hold one. The earned verdict expires by re-checking (withStaleness), which is
    // the honest way for it to go — not by being forgotten on the next tick.
    if (next.state === "unverified" && this.link.verifiedAt !== undefined) {
      next.state = this.link.state === "drifted" ? "drifted" : "ok";
      next.verifiedAt = this.link.verifiedAt;
      next.reason = this.link.reason;
    }
    // Carry what only an authenticated probe can learn — but drop it if the engine went away, so a
    // restarted engine at the same URL cannot keep showing the old one's version/environment.
    if (next.state !== "unreachable" && next.state !== "foreign") {
      next.version = next.version ?? this.link.version;
      next.environment = this.link.environment;
    }
    logProbe(target.url, POLL_PLAN[0].route, res.outcome, res.ms, next.state);
    logState(this.link, next);
    this.link = next;
    this.render();
    void this.readEnvironment();
    this.replayPendingRefresh();
  }

  /** Apply a settings change that arrived while a probe was in flight. */
  private replayPendingRefresh(): void {
    if (this.pendingTargetRefresh && !this.probing && !this.verifying && !this.busy) {
      this.pendingTargetRefresh = false;
      this.refreshTarget();
    }
  }

  /**
   * Best-effort, TOKENLESS: name the engine's active environment in the hover. Never fails the probe.
   *
   * It runs off the 15s poll, so it must never carry a bearer (CWE-613 — see the file header). That is
   * driven by {@link ENVIRONMENT_PLAN}'s `authenticated: false` rather than a literal `undefined` token
   * argument, so the tokenlessness is DATA that CI asserts. `aiPolicy.ts` reads the SAME route WITH a
   * bearer under `ASSIST_GATE_PLAN`, because it wants the identity-dependent `assist_permitted` and is
   * user-initiated; the difference between the two is deliberate (ADR 0110 amendment, BACKLOG #330).
   */
  private async readEnvironment(): Promise<void> {
    if (
      this.link.environment ||
      this.link.state === "unreachable" ||
      this.link.state === "foreign" ||
      this.link.state === "unknown"
    ) {
      return;
    }
    const gen = this.targetGen;
    const target = this.link.target;
    const outcome = (await this.runProbe(ENVIRONMENT_PLAN[0], target.url, PROBE_TIMEOUT_MS)).outcome;
    if (outcome.kind !== "ok" || gen !== this.targetGen) {
      return;
    }
    const env = (outcome.body as { environment?: unknown } | null)?.environment;
    if (typeof env === "string" && env) {
      this.link = { ...this.link, environment: env };
      this.render();
    }
  }

  /**
   * The DEEP probe — the only thing that can earn a green check. User-initiated only (click, activation,
   * post-promote), so the bearer it sends IS real user activity and does not falsify the idle clock.
   *
   * It hits a protected, permission-gated, NON-must-change-exempt route, because that is the only kind of
   * route whose success proves the session can actually do something. On success it also reads `/health`
   * WITH the token — the only way to learn the engine's version, which the tokenless poll never sees.
   */
  async verify(): Promise<void> {
    const target = this.link.target;
    if (
      this.link.state === "unreachable" ||
      this.link.state === "foreign" ||
      this.link.state === "unknown"
    ) {
      return; // nothing to verify against
    }
    // Never send a bearer to a target we would refuse credentials to (ADR 0035 / SEC-005).
    if (!assertTargetAllowed(target.url).ok) {
      return;
    }
    // No token is fatal only when the engine WANTS one. With auth disabled (`allow_no_auth`) the tokenless
    // /health discloses a version — state `unverified` — and the protected route answers anonymously too,
    // so bailing on a missing token here would strand that engine in `unverified` forever, with a
    // "Verify this session" action that could never do anything.
    const token = await peekToken(this.ctx, target.url);
    if (!token && this.link.state === "signedOut") {
      return; // honestly signed out — the shallow verdict already says so
    }
    this.verifying = true;
    const gen = this.targetGen;
    try {
      const deep = await this.runProbe(VERIFY_PLAN[0], target.url, PROBE_TIMEOUT_MS);
      if (gen !== this.targetGen) {
        return;
      }
      let next = classifyDeep(deep.outcome, this.link, Date.now());
      logProbe(target.url, VERIFY_PLAN[0].route, deep.outcome, deep.ms, next.state);

      if (next.state === "ok" || next.state === "drifted") {
        const health = await this.runProbe(VERIFY_PLAN[1], target.url, PROBE_TIMEOUT_MS);
        if (gen !== this.targetGen) {
          return;
        }
        logProbe(target.url, VERIFY_PLAN[1].route, health.outcome, health.ms, next.state);
        if (health.outcome.kind === "ok") {
          const version = readVersion(health.outcome.body);
          if (version) {
            next = { ...next, version };
          }
        }
      }
      logState(this.link, next);
      this.link = next;
      this.render();
    } finally {
      this.verifying = false;
      this.replayPendingRefresh();
    }
  }

  /** A full re-check with click-site feedback: shallow, then deep if there is anything to verify. */
  async recheck(): Promise<void> {
    if (this.disposed || this.busy) {
      return;
    }
    this.busy = true;
    this.render();
    const shown = Date.now();
    try {
      await this.poll();
      await this.verify();
    } finally {
      const remaining = MIN_SPINNER_MS - (Date.now() - shown);
      if (remaining > 0) {
        await new Promise((r) => setTimeout(r, remaining));
      }
      this.busy = false;
      this.render();
      this.replayPendingRefresh();
    }
  }

  /** True when the link was checked recently enough to act on without re-probing. */
  private isFresh(maxAgeMs: number): boolean {
    return (
      this.link.state !== "unknown" &&
      this.link.checkedAt !== undefined &&
      Date.now() - this.link.checkedAt < maxAgeMs
    );
  }

  /** Re-check ONLY if the link is stale. The click uses this so that opening the menu does not cost an
   *  HTTP round-trip the user has to sit and watch — the 15s timer already keeps the state current. */
  async ensureFresh(maxAgeMs: number): Promise<void> {
    if (this.isFresh(maxAgeMs)) {
      return;
    }
    await this.recheck();
  }

  /** Start periodic polling (and probe once immediately, including a deep verify). Idempotent. */
  start(): void {
    if (this.timer) {
      return;
    }
    void this.recheck();
    this.timer = setInterval(() => void this.poll(), POLL_INTERVAL_MS);
  }

  // ── Engine lifecycle (ADR 0112 — supersedes ADR 0110 §5) ─────────────────────────────────────────
  // The IDE may now RUN `serve`, not just hand over the command. Two safety properties, both enforced
  // here, keep this from reintroducing ADR 0110 §5's fork hazard (a stray `serve` that creates a rogue
  // empty database + bootstrap admin): it runs ONLY for a loopback target in a trusted workspace, and it
  // never SILENTLY creates a store — a run dir with no engine gets an explicit "create a new one" confirm.
  // Stop/Restart act ONLY on a process this IDE owns — never a port-kill of an engine started elsewhere.

  /** True when THIS IDE owns a live engine process (the terminal exists and its process has not exited). */
  private engineAlive(): boolean {
    return this.engineTerminal !== undefined && this.engineTerminal.exitStatus === undefined;
  }

  /** The lifecycle capabilities for the current target — the pure {@link planActions} gate. All the vscode
   *  and filesystem I/O the model must not do lives here. */
  controlContext(): EngineControlContext {
    const url = this.link.target.url;
    const ws = workspaceDir();
    // canControl: only a loopback engine can be run by the IDE (a remote one reads its own filesystem), only
    // in a trusted workspace (otherwise we must not exec a possibly repo-supplied .venv — SEC-004), and only
    // when there is a workspace for `serve` to run in.
    const canControl = ws !== undefined && vscode.workspace.isTrusted && isLocalEngine(url);
    const hasStore =
      canControl && ws !== undefined
        ? runDirHasEngine({
            serviceTomlExists: fs.existsSync(path.join(ws, serviceConfig())),
            dbFiles: dbFilesIn(ws),
          })
        : false;
    return { canControl, hasStore, weStartedIt: this.engineAlive() };
  }

  /** Run the interpreter preflight (`python -c "import messagefoundry.config.models"`) off the event loop,
   *  classifying the result so Start offers the RIGHT remedy for a missing interpreter vs missing deps. */
  private preflight(python: string): Promise<PreflightVerdict> {
    return new Promise((resolve) => {
      execFile(
        python,
        preflightArgs(),
        { cwd: workspaceDir(), timeout: 20_000 },
        (err, _stdout, stderr) => {
          const errno = (err as NodeJS.ErrnoException | null)?.code;
          if (errno === "ENOENT") {
            resolve(classifyPreflight({ code: -1, stderr: stderr ?? "", spawnError: errno }));
            return;
          }
          const code =
            err && typeof (err as { code?: unknown }).code === "number"
              ? (err as { code: number }).code
              : err
                ? 1
                : 0;
          resolve(classifyPreflight({ code, stderr: stderr ?? "" }));
        },
      );
    });
  }

  /** Start the local engine, guarding against a double-launch from a rapid second invocation (the
   *  confirm/preflight awaits leave a window before the terminal exists to be seen by engineAlive). */
  async startEngine(): Promise<void> {
    if (this.starting) {
      return;
    }
    this.starting = true;
    try {
      await this.launchEngine();
    } finally {
      this.starting = false;
    }
  }

  /** The actual launch — only ever entered through {@link startEngine}'s reentrancy guard. */
  private async launchEngine(): Promise<void> {
    const url = this.currentUrl();
    const ws = workspaceDir();
    if (!ws) {
      notify("open your engine's project folder first — the IDE runs `serve` in the workspace.");
      return;
    }
    if (!isLocalEngine(url)) {
      notify(`${url} is a remote engine — the IDE can only start a local (loopback) engine.`);
      return;
    }
    if (!vscode.workspace.isTrusted) {
      notify("trust this workspace to let the IDE run the engine.");
      return;
    }
    if (this.engineAlive()) {
      this.engineTerminal?.show();
      notify("the engine is already running from here — use Restart to reload it.");
      return;
    }
    // Fork guard (ADR 0110 §5): with no engine store here, starting would create a NEW database and a fresh
    // bootstrap admin. That is sometimes exactly what the user wants — but it must be a deliberate choice.
    if (!this.controlContext().hasStore) {
      const go = await vscode.window.showWarningMessage(
        `No engine store found in ${ws}. Starting here creates a NEW database and a bootstrap admin. Continue?`,
        { modal: true },
        "Create new engine",
      );
      if (go !== "Create new engine") {
        return;
      }
    }
    const python = pythonPath();
    const verdict = await this.preflight(python);
    if (verdict === "missingInterpreter") {
      const pick = await vscode.window.showErrorMessage(
        `MessageFoundry: could not run Python at "${python}".`,
        "Set the Python path",
      );
      if (pick) {
        await vscode.commands.executeCommand(
          "workbench.action.openSettings",
          "messagefoundry.pythonPath",
        );
      }
      return;
    }
    if (verdict === "missingDeps") {
      const pick = await vscode.window.showErrorMessage(
        `MessageFoundry: the Python at "${python}" cannot import MessageFoundry — its dependencies are not installed.`,
        "Set up environment",
        "Set the Python path",
      );
      if (pick === "Set up environment") {
        await this.setupEnvironment();
      } else if (pick === "Set the Python path") {
        await vscode.commands.executeCommand(
          "workbench.action.openSettings",
          "messagefoundry.pythonPath",
        );
      }
      return;
    }
    if (verdict === "error") {
      const pick = await vscode.window.showWarningMessage(
        "MessageFoundry: the engine interpreter preflight failed. Start anyway?",
        "Start anyway",
      );
      if (pick !== "Start anyway") {
        return;
      }
    }
    const { command, args } = buildServeInvocation({ python, configDir: configDir() });
    const term = vscode.window.createTerminal({
      name: "MessageFoundry Engine",
      shellPath: command,
      shellArgs: args,
      cwd: ws,
    });
    this.engineTerminal = term;
    term.show();
    // The interpreter path + serve args — no body, no token (AC-7); mirrors the copy-start log line.
    logAction("start engine", `${command} ${args.join(" ")}`);
    this.scheduleProbes();
  }

  /** Stop the engine this IDE started. Refuses to touch one it did not start. */
  async stopEngine(): Promise<void> {
    const url = this.currentUrl();
    if (!this.engineAlive()) {
      const reachable = this.link.state !== "unreachable" && this.link.state !== "unknown";
      this.engineTerminal = undefined;
      notify(
        reachable
          ? `the engine at ${url} was not started from this IDE — stop it where you launched it.`
          : "no engine is running from this IDE.",
      );
      return;
    }
    const term = this.engineTerminal;
    this.engineTerminal = undefined;
    term?.dispose(); // terminates the process; the store is WAL/crash-safe (reset_stale_inflight on restart)
    logAction("stop engine", url);
    notify("stopped the engine.");
    this.scheduleProbes();
  }

  /** Restart: stop the engine we own (waiting for the process to actually exit so the port frees), then start. */
  async restartEngine(): Promise<void> {
    if (this.engineAlive()) {
      const term = this.engineTerminal;
      this.engineTerminal = undefined;
      if (term) {
        const closed = awaitClose(term);
        term.dispose();
        await closed;
        await delay(500); // let the OS release the listening port before serve rebinds it
      }
    }
    await this.startEngine();
  }

  /** Bootstrap a Python environment (create `.venv` + install) for a workspace whose interpreter cannot
   *  import MessageFoundry — the "works from a fresh clone" path. Types the steps into a visible terminal. */
  async setupEnvironment(): Promise<void> {
    const ws = workspaceDir();
    if (!ws) {
      notify("open your project folder first.");
      return;
    }
    if (!vscode.workspace.isTrusted) {
      notify("trust this workspace to set up its Python environment.");
      return;
    }
    const plan = buildBootstrapPlan({
      hasPyproject: fs.existsSync(path.join(ws, "pyproject.toml")),
      platform: process.platform,
    });
    const go = await vscode.window.showWarningMessage(
      `Set up a Python environment in ${ws}? This runs:\n\n${plan.steps.join("\n")}`,
      { modal: true },
      "Set up",
    );
    if (go !== "Set up") {
      return;
    }
    const term = vscode.window.createTerminal({ name: "MessageFoundry Setup", cwd: ws });
    term.show();
    for (const step of plan.steps) {
      term.sendText(step);
    }
    logAction("set up environment", plan.steps.join(" ; "));
    notify("setting up the environment — when it finishes, click the engine item → Start the engine.");
  }

  /** Nudge the item toward the truth after a start/stop: re-probe a few times as the engine comes up or goes
   *  down, rather than waiting up to the 15s poll. `recheck` guards against overlap itself. */
  private scheduleProbes(): void {
    for (const ms of [1500, 4000, 8000]) {
      setTimeout(() => void this.recheck(), ms);
    }
  }

  dispose(): void {
    this.disposed = true;
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = undefined;
    }
    this.termWatch.dispose();
    this.item.dispose();
  }
}

/** MessageFoundry-prefixed info toast — the one user-facing acknowledgement the lifecycle actions emit. */
function notify(message: string): void {
  void vscode.window.showInformationMessage(`MessageFoundry: ${message}`);
}

/** Small delay used to let a stopped engine release its port before a restart rebinds it. */
function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Resolve once `term`'s process has actually closed (or after a 3s cap, so a restart never hangs). */
function awaitClose(term: vscode.Terminal): Promise<void> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      sub.dispose();
      resolve();
    }, 3000);
    const sub = vscode.window.onDidCloseTerminal((t) => {
      if (t === term) {
        clearTimeout(timer);
        sub.dispose();
        resolve();
      }
    });
  });
}

/** The `*.db` files directly under `dir` — a cheap "is there already an engine store here?" signal.
 *  A missing/unreadable directory is simply "no store" (never throws into the caller). */
function dbFilesIn(dir: string): string[] {
  try {
    return fs.readdirSync(dir).filter((f) => f.endsWith(".db"));
  } catch {
    return [];
  }
}

/** Two targets are the same instance AND the same configured set — `all` feeds the hover's environment
 *  list, so comparing only url+name left the hover showing pre-edit environments. */
function sameTarget(a: EngineStatusTarget, b: EngineStatusTarget): boolean {
  return (
    a.url === b.url &&
    a.name === b.name &&
    a.all.length === b.all.length &&
    a.all.every((e, i) => e.name === b.all[i].name && e.url === b.all[i].url)
  );
}

/** `$(icon) Label` → `Label` (inside a markdown link the leading glyph reads as noise). */
function stripIcon(label: string): string {
  return label.replace(/^\$\([a-z-]+\)\s*/, "");
}

/** `command:id?args` — args JSON-encoded per the VS Code command-URI contract. */
function commandUri(action: EngineAction): string {
  const args = action.args?.length ? `?${encodeURIComponent(JSON.stringify(action.args))}` : "";
  return `command:${action.command}${args}`;
}

/** The headline of the hover markdown ("**Engine ready**" → "Engine ready") — reused as the menu title. */
function firstLine(markdown: string): string {
  return (markdown.split("\n")[0] ?? "").replace(/\*\*/g, "").trim();
}

/**
 * Wire the engine status bar: the controller, its commands, the poll, and a re-resolve whenever the
 * engine settings change.
 */
export function registerEngineStatusBar(context: vscode.ExtensionContext): EngineStatusBar {
  const bar = new EngineStatusBar(context);

  const openConsole = async (path?: unknown): Promise<void> => {
    // The engine serves NO route at "/" — the old menu opened the bare engine URL and landed the user
    // on a FastAPI {"detail":"Not Found"}. The human-facing surface is the web console at /ui.
    const suffix = typeof path === "string" && path.startsWith("/") ? path : "/ui";
    const url = bar.currentUrl().replace(/\/+$/, "") + suffix;
    logAction("open web console", url);
    await vscode.env.openExternal(vscode.Uri.parse(url));
  };

  context.subscriptions.push(
    bar,

    vscode.commands.registerCommand("messagefoundry.engineStatusClicked", async () => {
      // Re-check only if the link is STALE. The 15s timer normally keeps it current, so the menu opens
      // instantly; making every click pay for an HTTP round-trip it must sit and watch is exactly the kind
      // of "responsive" that isn't. A stale/unknown link does spin — at the click site — before the menu.
      await bar.ensureFresh(CLICK_FRESH_MS);
      const link = bar.currentLink();
      const actions = planActions(link, Date.now(), bar.controlContext());
      const { tooltipMarkdown } = formatEngineStatus(link, Date.now());
      const pick = await vscode.window.showQuickPick(
        actions.map((a) => ({ label: a.label, detail: a.detail, action: a })),
        {
          // `title:` — NOT `placeHolder:`. The old menu put the engine URL in the placeholder, which
          // renders as grey "type to filter" hint text and vanishes the moment the user types. A title
          // is a persistent header, and a diagnosis belongs in a header.
          title: firstLine(tooltipMarkdown),
          placeHolder: link.reason ?? bar.currentUrl(),
        },
      );
      if (!pick) {
        return;
      }
      logAction(pick.action.command);
      // The ONLY permitted body of this handler (see the file header): dispatch a command id.
      await vscode.commands.executeCommand(pick.action.command, ...(pick.action.args ?? []));
    }),

    vscode.commands.registerCommand("messagefoundry.engineSignIn", async () => {
      const url = bar.currentUrl();
      logAction("sign in", url);
      const token = await signIn(context, url);
      if (token) {
        await bar.recheck(); // prove the new session works rather than assuming it does
      }
    }),

    vscode.commands.registerCommand("messagefoundry.engineSignOut", async () => {
      const url = bar.currentUrl();
      const revoked = await signOut(context, url);
      logAction("sign out", revoked ? `${url} (session revoked)` : `${url} (local token cleared only)`);
      // Say which actually happened. If the engine was unreachable we could not revoke, and the session
      // stays alive there until it times out — claiming a clean "signed out" would be a lie.
      void vscode.window.showInformationMessage(
        revoked
          ? `MessageFoundry: signed out of ${url}.`
          : `MessageFoundry: cleared the local token, but could not reach ${url} to revoke the session — it stays active there until it times out.`,
      );
      await bar.recheck();
    }),

    vscode.commands.registerCommand("messagefoundry.engineRecheck", () => bar.recheck()),
    vscode.commands.registerCommand("messagefoundry.engineShowLog", () => showEngineLog()),
    vscode.commands.registerCommand("messagefoundry.engineOpenConsole", openConsole),

    // Engine lifecycle (ADR 0112): run/stop/restart a LOCAL engine, and bootstrap its Python environment.
    // Each delegates to the controller, which enforces the loopback + trusted + owns-the-process guards.
    vscode.commands.registerCommand("messagefoundry.startEngine", () => bar.startEngine()),
    vscode.commands.registerCommand("messagefoundry.stopEngine", () => bar.stopEngine()),
    vscode.commands.registerCommand("messagefoundry.restartEngine", () => bar.restartEngine()),
    vscode.commands.registerCommand("messagefoundry.setupEnvironment", () => bar.setupEnvironment()),

    vscode.commands.registerCommand("messagefoundry.engineCopyStartCommand", async () => {
      // Deliberately COPY, not run. A terminal spawned here defaults its cwd to the workspace folder —
      // in a git worktree that has no service TOML and no store, so `serve` would quietly create a
      // BRAND-NEW empty database and a fresh bootstrap admin, forking the user's engine. Handing them
      // the command lets them run it where they mean to. No --db/--env overrides: the service TOML is
      // the authority on which store and which environment this engine is.
      const cmd = `python -m messagefoundry serve --config ${configDir()}`;
      await vscode.env.clipboard.writeText(cmd);
      logAction("copy start command", cmd);
      void vscode.window.showInformationMessage(
        `MessageFoundry: copied \`${cmd}\` — run it from your engine's checkout.`,
      );
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
