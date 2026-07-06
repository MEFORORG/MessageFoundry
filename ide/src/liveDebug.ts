// Live-debug v1 (#92): a deterministic, OFFLINE confidence loop. When toggled on, saving a config
// module re-runs `messagefoundry dryrun --json` against a chosen SYNTHETIC sample and renders
// CodeLens-only summaries above the `@router` / `@handler` / inbound() declarations — no AI, no engine,
// no inline decorations (those are v2). Everything here reads only structured `dryrun` JSON, never a
// message body, so nothing PHI-bearing is rendered (we also omit `--show-phi`, so the CLI redacts
// bodies at the source — defense in depth even though samples must be synthetic).
//
// SCOPE (bounded by what today's `dryrun --json` supports): each output row is ONE message and
// FLATTENS handler→delivery attribution (`deliveries` carry no `handler`). So a per-`@handler` Send
// count is only unambiguous when the whole run selected exactly one handler — that is the only case we
// attribute one. Multi-handler per-handler counts need a richer CLI shape (a v2 concern).
import * as fs from "node:fs";
import * as path from "node:path";
import * as vscode from "vscode";
import { configDir, isExecGated, messageSetsDir, runJson, workspaceDir } from "./cli";
import { findElements, isConfigFile, type ElementKind } from "./editorToolbar";

/**
 * The subset of a `dryrun --json` row this lane reads. Redeclared locally (not imported from
 * testBench.ts, whose `DryRunRow` is private) and deliberately minimal: only routing/disposition
 * fields, NOT `raw`/`summary`/`payload` — we never render a body, so PHI never reaches a lens.
 */
export interface LiveDryRunRow {
  inbound: string;
  disposition: string;
  handlers: string[];
  deliveries: { to: string }[];
  error: string | null;
}

/** The spawn seam. The real runner shells the CLI; tests inject a canned-JSON runner (no live engine). */
export type DryRunner = (samplePath: string, cwd: string) => Promise<LiveDryRunRow[]>;

/**
 * The production runner: `messagefoundry dryrun --config <cfg> --messages <sample> --json`. No
 * `--show-phi` — live-debug renders only names/dispositions/counts, so the CLI's default body redaction
 * is exactly right (and keeps PHI out of the spawn output entirely).
 */
export const cliDryRunner: DryRunner = (samplePath, cwd) =>
  runJson<LiveDryRunRow[]>(["dryrun", "--config", configDir(), "--messages", samplePath], cwd);

/** A config element located by line, with the name from its `("...")` argument (router/handler/inbound). */
export interface NamedElement {
  line: number; // 0-based
  kind: ElementKind;
  name: string | null;
}

const QUOTED_RE = /["']([^"']+)["']/;

/**
 * Locate `@router` / `@handler` / inbound() / outbound() declarations (reusing editorToolbar's line
 * scan so the two lens providers agree on what an "element" is) and pull each one's first quoted name
 * — the router name, the handler name, or the inbound connection name. Pure; unit-testable.
 */
export function namedElements(text: string): NamedElement[] {
  const lines = text.split(/\r?\n/);
  return findElements(text).map((el) => {
    const m = QUOTED_RE.exec(lines[el.line] ?? "");
    return { line: el.line, kind: el.kind, name: m ? m[1] : null };
  });
}

/** A rendered summary, as plain data (line + label). The provider maps these to `vscode.CodeLens`. */
export interface LiveLens {
  line: number; // 0-based
  title: string;
  tooltip?: string;
}

/** The aggregate of one dry-run over a (possibly multi-message) sample — everything the lenses need. */
export interface LiveSummary {
  messageCount: number;
  handlersUnion: string[]; // handler names selected across the run, first-seen order, de-duped
  dispositions: [string, number][]; // disposition → count, first-seen order
  totalSends: number; // total deliveries across every message
  soleHandler: string | null; // the one handler name IFF exactly one distinct handler ran (else null)
  errors: string[]; // distinct per-message error strings
}

/**
 * Fold a run's rows into a {@link LiveSummary}. `soleHandler` is set only when the entire run selected
 * exactly one distinct handler — the sole case in which `totalSends` is unambiguously that handler's,
 * given the CLI flattens handler→delivery attribution. Pure; unit-testable.
 */
export function summarize(rows: LiveDryRunRow[]): LiveSummary {
  const handlersUnion: string[] = [];
  const seen = new Set<string>();
  const dispCounts = new Map<string, number>();
  let totalSends = 0;
  const errors: string[] = [];
  for (const r of rows) {
    for (const h of r.handlers) {
      if (!seen.has(h)) {
        seen.add(h);
        handlersUnion.push(h);
      }
    }
    dispCounts.set(r.disposition, (dispCounts.get(r.disposition) ?? 0) + 1);
    totalSends += r.deliveries.length;
    if (r.error) {
      errors.push(r.error);
    }
  }
  return {
    messageCount: rows.length,
    handlersUnion,
    dispositions: [...dispCounts.entries()],
    totalSends,
    soleHandler: seen.size === 1 ? handlersUnion[0] : null,
    errors: [...new Set(errors)],
  };
}

/**
 * Build the CodeLens summaries for one config document's elements against a run summary. Attaches the
 * disposition to inbound() lines, the routing decision to `@router` lines, and a Send count to a
 * `@handler` line ONLY when it is the run's sole handler (unambiguous). Pure; unit-testable.
 */
export function buildLiveLenses(
  elements: NamedElement[],
  summary: LiveSummary,
  label: string,
): LiveLens[] {
  const out: LiveLens[] = [];
  const dispText = summary.dispositions.length
    ? summary.dispositions
        .map(([d, n]) => (summary.messageCount === 1 ? d : `${n} ${d}`))
        .join(" · ")
    : "no messages";
  for (const el of elements) {
    if (el.kind === "inbound") {
      const prefix = label ? `${label}: ` : "";
      out.push({
        line: el.line,
        title: `$(pulse) ${prefix}${dispText}`,
        tooltip: summary.errors.length
          ? `Errors: ${summary.errors.join("; ")}`
          : `Live dry-run of ${label || "the selected sample"} (${summary.messageCount} message(s)).`,
      });
    } else if (el.kind === "router") {
      const routed = summary.handlersUnion.length
        ? `[${summary.handlersUnion.join(", ")}]`
        : "(nowhere)";
      out.push({
        line: el.line,
        title: `$(arrow-right) routed → ${routed}`,
        tooltip: "Handlers this router selected across the sample run (from dryrun `handlers`).",
      });
    } else if (el.kind === "handler" && summary.soleHandler !== null && el.name === summary.soleHandler) {
      const n = summary.totalSends;
      out.push({
        line: el.line,
        title: `$(arrow-small-right) ${n} Send${n === 1 ? "" : "s"}`,
        tooltip:
          "Send count is attributable here because exactly one handler ran this sample. v1 flattens " +
          "handler→delivery attribution, so per-handler counts for a multi-handler module are v2.",
      });
    }
  }
  return out;
}

/**
 * The live-debug controller: owns the on/off state, the chosen sample, the last run's rows, a debounced
 * save watcher, and its own CodeLens provider. Off by default. The dry-run spawn is injectable so the
 * whole pipeline is testable with canned JSON and no engine.
 */
export class LiveDebugController implements vscode.CodeLensProvider, vscode.Disposable {
  private readonly changed = new vscode.EventEmitter<void>();
  readonly onDidChangeCodeLenses = this.changed.event;

  private enabled = false;
  private running = false;
  private rows: LiveDryRunRow[] | null = null;
  private error: string | null = null;
  private samplePath: string | undefined;
  private sampleLabel: string | undefined;
  private runToken = 0;
  private debounceTimer: ReturnType<typeof setTimeout> | undefined;
  private statusBar: vscode.StatusBarItem | undefined;

  constructor(private readonly runner: DryRunner = cliDryRunner) {}

  setStatusBar(item: vscode.StatusBarItem): void {
    this.statusBar = item;
    this.updateStatus();
  }

  isEnabled(): boolean {
    return this.enabled;
  }

  private updateStatus(): void {
    const sb = this.statusBar;
    if (!sb) {
      return;
    }
    if (!this.enabled) {
      sb.text = "$(circle-outline) MEFOR Live: Off";
      sb.tooltip = "MessageFoundry live-debug is off. Click to re-run a synthetic sample on every save.";
      return;
    }
    if (this.running) {
      sb.text = "$(sync~spin) MEFOR Live…";
      sb.tooltip = "Running a live dry-run…";
      return;
    }
    if (this.error) {
      sb.text = "$(error) MEFOR Live";
      sb.tooltip = `Last live dry-run failed: ${this.error}`;
      return;
    }
    sb.text = "$(pulse) MEFOR Live: On";
    sb.tooltip = `Live-debug on save · sample: ${this.sampleLabel ?? "(none)"}. Click to turn off.`;
  }

  /** Flip on/off. Turning on picks a synthetic sample (if none) and does a first run; off clears lenses. */
  async toggle(): Promise<void> {
    if (this.enabled) {
      this.enabled = false;
      this.rows = null;
      this.error = null;
      this.updateStatus();
      this.changed.fire();
      return;
    }
    this.enabled = true;
    const ok = await this.ensureSample();
    if (!ok) {
      this.enabled = false;
      this.updateStatus();
      return;
    }
    this.updateStatus();
    await this.run();
  }

  /** Debounced save hook: re-run only when on, trusted, and the saved file is a config .py module. */
  onSave(doc: vscode.TextDocument): void {
    if (!this.enabled || isExecGated() || doc.languageId !== "python") {
      return;
    }
    if (!isConfigFile(doc.uri.fsPath, workspaceDir(), configDir())) {
      return;
    }
    this.scheduleRun();
  }

  private scheduleRun(): void {
    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer);
    }
    this.debounceTimer = setTimeout(() => {
      this.debounceTimer = undefined;
      void this.run();
    }, this.debounceMs());
  }

  private debounceMs(): number {
    const v = vscode.workspace
      .getConfiguration("messagefoundry")
      .get<number>("liveDebug.debounceMs", 400);
    return typeof v === "number" && Number.isFinite(v) && v >= 0 ? Math.floor(v) : 400;
  }

  private async ensureSample(): Promise<boolean> {
    if (this.samplePath && fs.existsSync(this.samplePath)) {
      return true;
    }
    const ws = workspaceDir();
    if (!ws) {
      void vscode.window.showInformationMessage("MEFOR Live: open a workspace folder first.");
      return false;
    }
    const dir = messageSetsDir();
    const abs = path.isAbsolute(dir) ? dir : path.join(ws, dir);
    let files: string[] = [];
    try {
      files = fs.existsSync(abs)
        ? fs.readdirSync(abs).filter((f) => f.toLowerCase().endsWith(".hl7")).sort()
        : [];
    } catch {
      files = [];
    }
    if (files.length === 0) {
      void vscode.window.showInformationMessage(
        `MEFOR Live: add a synthetic .hl7 sample under ${dir} to use live-debug (synthetic only — never real PHI).`,
      );
      return false;
    }
    const pick = await vscode.window.showQuickPick(files, {
      placeHolder: "Pick a synthetic sample for live-debug (never real PHI)",
    });
    if (!pick) {
      return false;
    }
    this.samplePath = path.join(abs, pick);
    this.sampleLabel = pick;
    return true;
  }

  private async run(): Promise<void> {
    if (!this.enabled) {
      return;
    }
    const ws = workspaceDir();
    if (!ws) {
      return;
    }
    if (!this.samplePath) {
      const ok = await this.ensureSample();
      if (!ok) {
        return;
      }
    }
    if (isExecGated()) {
      this.rows = null;
      this.error = "workspace not trusted — live-debug disabled until you trust this workspace";
      this.updateStatus();
      this.changed.fire();
      return;
    }
    // this.samplePath is set by ensureSample above.
    await this.runWith(this.samplePath as string, ws);
  }

  /**
   * Run the (injected) dry-runner against a sample and store the result. A per-run token discards a
   * superseded run's late result, so a rapid save-storm always renders the newest run only. Public so
   * a test can drive it with a canned runner (no sample-pick, no workspace).
   */
  async runWith(samplePath: string, cwd: string): Promise<void> {
    const token = ++this.runToken;
    this.running = true;
    this.updateStatus();
    let rows: LiveDryRunRow[] | null = null;
    let err: string | null = null;
    try {
      rows = await this.runner(samplePath, cwd);
    } catch (e) {
      err = e instanceof Error ? e.message : String(e);
    }
    if (token !== this.runToken) {
      return; // superseded by a newer run — drop this stale result
    }
    this.running = false;
    this.samplePath = samplePath;
    this.sampleLabel = path.basename(samplePath);
    this.rows = rows;
    this.error = err;
    this.updateStatus();
    this.changed.fire();
  }

  /** Compute the lenses for a document's text against the last run — pure enough to test directly. */
  lensesForText(text: string): LiveLens[] {
    if (this.error) {
      return [
        {
          line: 0,
          title: `$(error) MEFOR Live: ${this.error}`,
          tooltip: "The last live dry-run failed. Fix the config or pick another sample.",
        },
      ];
    }
    if (!this.rows) {
      return [];
    }
    return buildLiveLenses(namedElements(text), summarize(this.rows), this.sampleLabel ?? "");
  }

  provideCodeLenses(document: vscode.TextDocument): vscode.CodeLens[] {
    if (!this.enabled) {
      return [];
    }
    if (!isConfigFile(document.uri.fsPath, workspaceDir(), configDir())) {
      return [];
    }
    return this.lensesForText(document.getText()).map(
      (l) =>
        new vscode.CodeLens(new vscode.Range(l.line, 0, l.line, 0), {
          // An empty command renders the summary as a non-clickable label (info-only, per v1 scope).
          title: l.title,
          command: "",
          tooltip: l.tooltip,
        }),
    );
  }

  dispose(): void {
    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer);
    }
    this.changed.dispose();
  }
}

/**
 * Wire live-debug into the extension: a left status-bar toggle (off by default), the toggle command,
 * this lane's own CodeLens provider (VS Code allows several per language — this coexists with the
 * editor-toolbar provider), and a save watcher. Returns the controller (for tests / callers).
 */
export function registerLiveDebug(context: vscode.ExtensionContext): LiveDebugController {
  const controller = new LiveDebugController();
  const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  statusBar.command = "messagefoundry.toggleLiveDebug";
  controller.setStatusBar(statusBar);
  statusBar.show();

  context.subscriptions.push(
    controller,
    statusBar,
    vscode.commands.registerCommand("messagefoundry.toggleLiveDebug", () => void controller.toggle()),
    vscode.languages.registerCodeLensProvider({ language: "python" }, controller),
    vscode.workspace.onDidSaveTextDocument((doc) => controller.onSave(doc)),
  );
  return controller;
}
