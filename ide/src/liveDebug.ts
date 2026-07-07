// Live-debug (#92): a deterministic, OFFLINE confidence loop. When toggled on, saving a config module
// re-runs `messagefoundry dryrun --trace json` against a chosen SYNTHETIC sample and renders, over the
// active module: (v1) CodeLens summaries above the `@router` / `@handler` / inbound() declarations, and
// (v2) per-statement inline `after`-text decorations + hover showing the locals each executed line
// assigned and the `msg[...]` writes it made. No AI, no engine, no dispatch — it reads only the
// structured `dryrun --trace` JSON.
//
// PHI (CLAUDE.md §9). The inline values are message-derived, hence PHI, and are screenshot-/screenshare-
// capturable. They render as a redacted placeholder (`▸ ⋯`) BY DEFAULT. Real values appear ONLY under a
// SEPARATE, independent "reveal values" toggle (`messagefoundry.toggleRevealValues`, off by default)
// that is NOT the "MEFOR Live" toggle: only when it is on do we pass `--show-phi` to the CLI, so real
// values never even leave the Python process otherwise. Samples must be synthetic (under messageSetsDir).
//
// SCOPE (bounded by the CLI shape): each traced entry is ONE message and FLATTENS handler→delivery
// attribution (top-level `sends` carry no `handler`). So a per-`@handler` Send count is only unambiguous
// when the whole run selected exactly one handler — the only case we attribute one (unchanged from v1).
import * as fs from "node:fs";
import * as path from "node:path";
import * as vscode from "vscode";
import { configDir, isExecGated, messageSetsDir, runJson, workspaceDir } from "./cli";
import { findElements, isConfigFile, type ElementKind } from "./editorToolbar";

/**
 * The subset of a traced `dryrun` entry this lane reads for the v1 CodeLens summary — deliberately
 * minimal: only routing/disposition fields, NOT any body. Derived from a {@link LiveTraceEntry} via
 * {@link rowsFromTrace}, so the same fold ({@link summarize}) drives the summaries as before.
 */
export interface LiveDryRunRow {
  inbound: string;
  disposition: string;
  handlers: string[];
  deliveries: { to: string }[];
  error: string | null;
}

// --- traced dry-run schema (messagefoundry/pipeline/dryrun_trace.py, ADR 0072) -------------------
// A JSON-safe captured value. Without --show-phi the CLI collapses every value to the string
// "REDACTED"; with it, scalars pass through (strings/numbers/bools/null, length-capped upstream).
export type TraceValue = string | number | boolean | null;

/** One executed source line: the locals it (re)bound and the `msg[...]`/`msg.set(...)` writes it made. */
export interface TraceEvent {
  line: number; // 1-based (Python line number)
  event: string; // always "line"
  assigned?: Record<string, TraceValue>;
  writes?: { path: string; value: TraceValue }[];
}

/** A live db_lookup/fhir_lookup that a pure preview cannot evaluate (raised + re-raised by the tracer). */
export interface TraceAnnotation {
  line: number | null; // 1-based Handler line the call was made on (or null → fall back to def_line)
  kind: string; // "live_lookup_skipped"
  call: string; // "db_lookup" | "fhir_lookup"
}

/** One Router/Handler invocation's execution trace. */
export interface TraceInvocation {
  kind: string; // "router" | "handler"
  name: string;
  module: string | null;
  file: string | null; // absolute path of the module that defines the fn
  def_line: number | null; // 1-based
  events: TraceEvent[];
  disposition: string;
  sends: { outbound: string }[];
  routed_to: string[];
  annotations: TraceAnnotation[];
  truncated?: boolean;
}

/** One traced message (one array element of `dryrun --trace json`). */
export interface LiveTraceEntry {
  source?: string;
  path?: string;
  inbound: string;
  disposition: string;
  handlers: string[];
  sends: { outbound: string }[];
  error: string | null;
  trace_ok?: boolean;
  invocations: TraceInvocation[];
}

/**
 * The spawn seam. The real runner shells the CLI; tests inject a canned trace-JSON runner (no live
 * engine — the CI ide job has no Python). `showPhi` is threaded through so the runner can decide whether
 * to request real values; it maps 1:1 to the "reveal values" toggle, NEVER to "MEFOR Live".
 */
export type TraceRunner = (
  samplePath: string,
  cwd: string,
  showPhi: boolean,
) => Promise<LiveTraceEntry[]>;

/**
 * Assemble the `dryrun --trace json` argv. `--show-phi` is appended IFF `showPhi` — the single point
 * where the reveal-values gate turns into a real-value request. Pure (no vscode) so it is unit-testable.
 */
export function buildTraceArgs(cfgDir: string, samplePath: string, showPhi: boolean): string[] {
  const args = ["dryrun", "--config", cfgDir, "--messages", samplePath, "--trace", "json"];
  if (showPhi) {
    args.push("--show-phi");
  }
  return args;
}

/**
 * The production runner: `messagefoundry dryrun --config <cfg> --messages <sample> --trace json
 * [--show-phi]`. `--show-phi` is present ONLY when the reveal-values toggle is on; otherwise the CLI
 * redacts every captured value at the source, so no PHI leaves the Python process.
 */
export const cliTraceRunner: TraceRunner = (samplePath, cwd, showPhi) =>
  runJson<LiveTraceEntry[]>(buildTraceArgs(configDir(), samplePath, showPhi), cwd);

/** Project the v1 CodeLens fields out of the richer trace entries (the summary path is unchanged). */
export function rowsFromTrace(entries: LiveTraceEntry[]): LiveDryRunRow[] {
  return entries.map((e) => ({
    inbound: e.inbound,
    disposition: e.disposition,
    handlers: e.handlers,
    deliveries: e.sends.map((s) => ({ to: s.outbound })),
    error: e.error,
  }));
}

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

// --- v2 inline decorations (per-statement values + hover) ----------------------------------------

/** The redacted placeholder shown in place of any real value while "reveal values" is off. */
export const REVEAL_PLACEHOLDER = "⋯";
/** The exact string the CLI substitutes for a captured value when `--show-phi` was NOT passed. */
const TRACE_REDACTED = "REDACTED";
const VALUE_MARKER = "▸";
const WARNING_TEXT = "⚠ live lookup — not evaluated in preview";

/** One line's inline rendering: the `after`-text, its hover markdown, and whether it is a warning. */
export interface InlineValue {
  line: number; // 0-based (VS Code coordinates)
  after: string; // the decoration's `after` contentText (redacted unless reveal is on)
  hover: string; // markdown for the line's full per-line values
  kind: "value" | "warning";
}

/** A single captured item on a line: a local assignment, or a `msg[...]` write. */
interface LineItem {
  label: string; // local name, or `msg["PID-5.1"]`
  value: TraceValue;
}

/**
 * Render one captured value. Off-reveal it is ALWAYS the placeholder — a defense-in-depth belt beyond
 * the CLI redaction, so a value can never leak through this path even if a caller mis-wired the gate.
 * On-reveal a value the CLI still redacted (e.g. length-capped) also shows the placeholder.
 */
function renderValue(value: TraceValue, reveal: boolean): string {
  if (!reveal || value === TRACE_REDACTED) {
    return REVEAL_PLACEHOLDER;
  }
  return JSON.stringify(value); // "SMITH" / 12345 / true / null — quotes strings, leaves scalars bare
}

/** The concise inline `after`-text: a single placeholder off-reveal; value(s) on-reveal. */
function renderAfter(items: LineItem[], reveal: boolean): string {
  if (!reveal) {
    return `${VALUE_MARKER} ${REVEAL_PLACEHOLDER}`;
  }
  if (items.length === 1) {
    return `${VALUE_MARKER} ${renderValue(items[0].value, true)}`;
  }
  return `${VALUE_MARKER} ${items.map((it) => `${it.label} = ${renderValue(it.value, true)}`).join(", ")}`;
}

/** The verbose hover: a `name = value` list, PHI-gated exactly like the inline text. */
function renderHover(items: LineItem[], reveal: boolean): string {
  const header = reveal
    ? "**Live values** (synthetic sample)"
    : "**Live values** — hidden. Toggle *MessageFoundry: Reveal Values* to show (PHI; synthetic only).";
  const body = items.map((it) => `- \`${it.label}\` = \`${renderValue(it.value, reveal)}\``);
  return [header, ...body].join("\n");
}

/**
 * Fold a set of invocations (already filtered to ONE module) into per-line inline decorations. Locals
 * assigned and `msg[...]` writes are attributed to their producing line (`event.line`); across multiple
 * traced messages the LAST invocation touching a line wins (the newest message's values). A
 * `live_lookup_skipped` annotation renders a warning on its line and suppresses any value there. Pure.
 */
export function inlineValuesFor(invocations: TraceInvocation[], reveal: boolean): InlineValue[] {
  const byLine = new Map<number, LineItem[]>(); // 1-based line → items
  const warnings = new Map<number, string>(); // 1-based line → call name
  for (const inv of invocations) {
    const local = new Map<number, LineItem[]>();
    for (const ev of inv.events) {
      const items = local.get(ev.line) ?? [];
      for (const [name, value] of Object.entries(ev.assigned ?? {})) {
        items.push({ label: name, value });
      }
      for (const w of ev.writes ?? []) {
        items.push({ label: `msg["${w.path}"]`, value: w.value });
      }
      if (items.length > 0) {
        local.set(ev.line, items);
      }
    }
    for (const [line, items] of local) {
      byLine.set(line, items); // last invocation (newest message) wins for a shared line
    }
    for (const ann of inv.annotations) {
      if (ann.kind === "live_lookup_skipped") {
        warnings.set(ann.line ?? inv.def_line ?? 1, ann.call);
      }
    }
  }
  const out: InlineValue[] = [];
  for (const [line, items] of byLine) {
    if (warnings.has(line)) {
      continue; // a live-lookup line raised before assigning — the warning speaks for it
    }
    out.push({
      line: line - 1,
      after: renderAfter(items, reveal),
      hover: renderHover(items, reveal),
      kind: "value",
    });
  }
  for (const [line, call] of warnings) {
    out.push({
      line: line - 1,
      after: WARNING_TEXT,
      hover: `\`${call}\` is a live, read-only lookup — not evaluated in this offline preview.`,
      kind: "warning",
    });
  }
  return out.sort((a, b) => a.line - b.line);
}

/** Collect every invocation across the run whose defining file is `fsPath` (the active module). */
export function invocationsForFile(entries: LiveTraceEntry[], fsPath: string): TraceInvocation[] {
  const target = path.resolve(fsPath);
  const out: TraceInvocation[] = [];
  for (const e of entries) {
    for (const inv of e.invocations) {
      if (inv.file && path.resolve(inv.file) === target) {
        out.push(inv);
      }
    }
  }
  return out;
}

/**
 * The live-debug controller: owns the on/off state, a SEPARATE reveal-values state, the chosen sample,
 * the last run's rows + trace, a debounced save watcher, its CodeLens provider, and the inline
 * decorations. Both toggles are off by default. The dry-run spawn is injectable so the whole pipeline is
 * testable with canned trace JSON and no engine.
 */
export class LiveDebugController implements vscode.CodeLensProvider, vscode.Disposable {
  private readonly changed = new vscode.EventEmitter<void>();
  readonly onDidChangeCodeLenses = this.changed.event;

  private enabled = false;
  private running = false;
  // Reveal-values is a SEPARATE, independent gate from `enabled`. OFF by default; only when it is on do
  // we request real values (--show-phi). Toggling "MEFOR Live" never changes it, and vice-versa.
  private revealValues = false;
  private rows: LiveDryRunRow[] | null = null;
  private entries: LiveTraceEntry[] | null = null; // last traced run (drives the inline decorations)
  private error: string | null = null;
  private samplePath: string | undefined;
  private sampleLabel: string | undefined;
  private runToken = 0;
  private debounceTimer: ReturnType<typeof setTimeout> | undefined;
  private statusBar: vscode.StatusBarItem | undefined;
  private revealStatusBar: vscode.StatusBarItem | undefined;
  private valueDecoration: vscode.TextEditorDecorationType | undefined;
  private warnDecoration: vscode.TextEditorDecorationType | undefined;

  constructor(private readonly runner: TraceRunner = cliTraceRunner) {}

  setStatusBar(item: vscode.StatusBarItem): void {
    this.statusBar = item;
    this.updateStatus();
  }

  /** Wire the SEPARATE reveal-values status item (its own command/toggle — never the Live toggle). */
  setRevealStatusBar(item: vscode.StatusBarItem): void {
    this.revealStatusBar = item;
    this.updateRevealStatus();
  }

  /** Inject the two inline-decoration types (created in {@link registerLiveDebug}); disposed by it. */
  setDecorationTypes(
    value: vscode.TextEditorDecorationType,
    warn: vscode.TextEditorDecorationType,
  ): void {
    this.valueDecoration = value;
    this.warnDecoration = warn;
  }

  isEnabled(): boolean {
    return this.enabled;
  }

  isRevealingValues(): boolean {
    return this.revealValues;
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

  /** Reflect the reveal-values gate in its OWN status item (distinct icon/label from "MEFOR Live"). */
  private updateRevealStatus(): void {
    const sb = this.revealStatusBar;
    if (!sb) {
      return;
    }
    if (this.revealValues) {
      sb.text = "$(eye) Values: Shown";
      sb.tooltip =
        "Live-debug inline values are REVEALED (PHI, screenshot-capturable). Click to hide. Synthetic samples only.";
    } else {
      sb.text = "$(eye-closed) Values: Hidden";
      sb.tooltip =
        "Live-debug inline values are hidden (PHI-safe). Click to reveal real values — synthetic samples only.";
    }
  }

  /** Flip on/off. Turning on picks a synthetic sample (if none) and does a first run; off clears lenses. */
  async toggle(): Promise<void> {
    if (this.enabled) {
      this.enabled = false;
      this.rows = null;
      this.entries = null;
      this.error = null;
      this.updateStatus();
      this.changed.fire();
      this.refreshActiveDecorations();
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

  /**
   * Flip the SEPARATE reveal-values gate. This is NOT the Live toggle: it only decides whether real
   * values are requested. Turning it OFF drops any in-memory trace (which may hold real values) and
   * re-decorates as redacted immediately; when Live is on it re-runs so the store reflects the new gate.
   * Independent of Live: toggling it while Live is off just records the preference (no run, no reveal).
   */
  async toggleReveal(): Promise<void> {
    this.revealValues = !this.revealValues;
    if (!this.revealValues) {
      this.entries = null; // never keep real values around once hidden
    }
    this.updateRevealStatus();
    this.refreshActiveDecorations();
    if (this.enabled && this.samplePath) {
      await this.run(); // re-fetch with/without --show-phi to match the new gate
    }
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
      this.entries = null;
      this.error = "workspace not trusted — live-debug disabled until you trust this workspace";
      this.updateStatus();
      this.changed.fire();
      this.refreshActiveDecorations();
      return;
    }
    // this.samplePath is set by ensureSample above.
    await this.runWith(this.samplePath as string, ws);
  }

  /**
   * Run the (injected) trace-runner against a sample and store the result. The current reveal-values
   * gate is threaded through as `showPhi` — the ONLY place --show-phi is (conditionally) requested. A
   * per-run token discards a superseded run's late result, so a rapid save-storm always renders the
   * newest run only. Public so a test can drive it with a canned runner (no sample-pick, no workspace).
   */
  async runWith(samplePath: string, cwd: string): Promise<void> {
    const token = ++this.runToken;
    this.running = true;
    this.updateStatus();
    let entries: LiveTraceEntry[] | null = null;
    let err: string | null = null;
    try {
      entries = await this.runner(samplePath, cwd, this.revealValues);
    } catch (e) {
      err = e instanceof Error ? e.message : String(e);
    }
    if (token !== this.runToken) {
      return; // superseded by a newer run — drop this stale result
    }
    this.running = false;
    this.samplePath = samplePath;
    this.sampleLabel = path.basename(samplePath);
    this.entries = entries;
    this.rows = entries ? rowsFromTrace(entries) : null;
    this.error = err;
    this.updateStatus();
    this.changed.fire();
    this.refreshActiveDecorations();
  }

  // --- inline decorations ----------------------------------------------------------------------

  /** Re-apply inline decorations to the active editor (called after a run, a toggle, or an editor swap). */
  refreshActiveDecorations(): void {
    this.applyDecorations(vscode.window.activeTextEditor);
  }

  /**
   * Render (or clear) the per-line inline value decorations on `editor`. Clears whenever Live is off,
   * a run errored, there's no trace, or the editor isn't a config module. Otherwise it maps the active
   * module's invocations to redacted-by-default (real only when reveal is on) `after`-text + hover.
   */
  private applyDecorations(editor: vscode.TextEditor | undefined): void {
    if (!editor || !this.valueDecoration || !this.warnDecoration) {
      return;
    }
    const clear = (): void => {
      editor.setDecorations(this.valueDecoration as vscode.TextEditorDecorationType, []);
      editor.setDecorations(this.warnDecoration as vscode.TextEditorDecorationType, []);
    };
    if (!this.enabled || this.error || !this.entries) {
      clear();
      return;
    }
    if (!isConfigFile(editor.document.uri.fsPath, workspaceDir(), configDir())) {
      clear();
      return;
    }
    const invs = invocationsForFile(this.entries, editor.document.uri.fsPath);
    const inline = inlineValuesFor(invs, this.revealValues);
    const values: vscode.DecorationOptions[] = [];
    const warns: vscode.DecorationOptions[] = [];
    const lastLine = editor.document.lineCount - 1;
    for (const iv of inline) {
      if (iv.line < 0 || iv.line > lastLine) {
        continue; // trace line beyond the (possibly edited) buffer — skip rather than throw
      }
      const eol = editor.document.lineAt(iv.line).text.length;
      const opt: vscode.DecorationOptions = {
        range: new vscode.Range(iv.line, eol, iv.line, eol),
        hoverMessage: new vscode.MarkdownString(iv.hover),
        renderOptions: { after: { contentText: `  ${iv.after}` } },
      };
      (iv.kind === "warning" ? warns : values).push(opt);
    }
    editor.setDecorations(this.valueDecoration, values);
    editor.setDecorations(this.warnDecoration, warns);
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
 * Wire live-debug into the extension: two left status-bar items — the "MEFOR Live" toggle and the
 * SEPARATE "reveal values" toggle (both off by default) — their commands, this lane's own CodeLens
 * provider (VS Code allows several per language — this coexists with the editor-toolbar provider), the
 * inline-decoration types, a save watcher, and an active-editor watcher (re-decorate on editor swaps).
 * Returns the controller (for tests / callers).
 */
export function registerLiveDebug(context: vscode.ExtensionContext): LiveDebugController {
  const controller = new LiveDebugController();
  const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  statusBar.command = "messagefoundry.toggleLiveDebug";
  controller.setStatusBar(statusBar);
  statusBar.show();

  // The reveal-values control is its OWN status item + command, independent of "MEFOR Live".
  const revealBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 49);
  revealBar.command = "messagefoundry.toggleRevealValues";
  controller.setRevealStatusBar(revealBar);
  revealBar.show();

  // Inline `after`-text decorations: dimmed for values, amber for the live-lookup warning. contentText
  // is set per-decoration (it varies per line); color/style live on the shared type.
  const after = { fontStyle: "italic", margin: "0 0 0 1rem" };
  const valueDecoration = vscode.window.createTextEditorDecorationType({
    after: { ...after, color: new vscode.ThemeColor("editorCodeLens.foreground") },
    rangeBehavior: vscode.DecorationRangeBehavior.ClosedClosed,
  });
  const warnDecoration = vscode.window.createTextEditorDecorationType({
    after: { ...after, color: new vscode.ThemeColor("editorWarning.foreground") },
    rangeBehavior: vscode.DecorationRangeBehavior.ClosedClosed,
  });
  controller.setDecorationTypes(valueDecoration, warnDecoration);

  context.subscriptions.push(
    controller,
    statusBar,
    revealBar,
    valueDecoration,
    warnDecoration,
    vscode.commands.registerCommand("messagefoundry.toggleLiveDebug", () => void controller.toggle()),
    vscode.commands.registerCommand(
      "messagefoundry.toggleRevealValues",
      () => void controller.toggleReveal(),
    ),
    vscode.languages.registerCodeLensProvider({ language: "python" }, controller),
    vscode.workspace.onDidSaveTextDocument((doc) => controller.onSave(doc)),
    vscode.window.onDidChangeActiveTextEditor(() => controller.refreshActiveDecorations()),
  );
  return controller;
}
