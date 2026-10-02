// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Live-debug (#92): a deterministic, OFFLINE confidence loop. When toggled on, saving a config module
// re-runs `messagefoundry dryrun --trace json` against a chosen SYNTHETIC sample and renders, over the
// active module: (v1) CodeLens summaries above the `@router` / `@handler` / inbound() declarations, and
// (v2) per-statement inline `after`-text decorations + hover showing the locals each executed line
// assigned and the `msg[...]` writes it made. No AI, no engine, no dispatch — it reads only the
// structured `dryrun --trace` JSON.
//
// PHI (CLAUDE.md §9). The inline values are message-derived, hence PHI, and are screenshot-/screenshare-
// capturable. They render as a redacted placeholder (`▸ ⋯`) BY DEFAULT. Real values appear ONLY for ONE
// run the user asks for by name (`messagefoundry.revealValuesOnce`, ASVS 14.2.6, vault BACKLOG #1187),
// and for ONE message of that run: a multi-message sample asks which one first (owner ruling R15):
// that run alone passes `--show-phi` to the CLI, and every later run is masked again. The reveal is never
// a session state, so a run the user did not ask for never carries real values, and real values never
// even leave the Python process otherwise. Samples must be synthetic (under messageSetsDir). The same
// holds for the per-message error text: a masked run's lens tooltip shows only how many messages
// failed, because the CLI's masked error is scrubbed rather than removed (vault BACKLOG #1187, d1).
//
// SCOPE (bounded by the CLI shape): each traced entry is ONE message and FLATTENS handler→delivery
// attribution (top-level `sends` carry no `handler`). So a per-`@handler` Send count is only unambiguous
// when the whole run selected exactly one handler — the only case we attribute one (unchanged from v1).
import * as fs from "node:fs";
import * as path from "node:path";
import * as vscode from "vscode";
import { configDir, isExecGated, messageSetsDir, runJson, workspaceDir } from "./cli";
import { findElements, isConfigFile } from "./editorToolbar";
import {
  buildLiveLenses,
  maskedMessagesOf,
  revealPickItems,
  revealedEntry,
  revealedLabel,
  rowsFromTrace,
  summarize,
  type LiveDryRunRow,
  type LiveLens,
  type LiveTraceEntry,
  type MaskedMessage,
  type NamedElement,
  type RevealFocus,
  type TraceInvocation,
  type TraceValue,
} from "./liveDebugModel";

// The pure half lives in liveDebugModel.ts so the unit suite can run it; re-export it so every
// importer of this module keeps working unchanged.
export {
  buildLiveLenses,
  inboundTooltip,
  maskedMessagesOf,
  revealPickItems,
  revealedEntry,
  revealedLabel,
  rowsFromTrace,
  summarize,
  type LiveDryRunRow,
  type LiveLens,
  type LiveSummary,
  type LiveTraceEntry,
  type MaskedMessage,
  type NamedElement,
  type RevealFocus,
  type TraceAnnotation,
  type TraceEvent,
  type TraceInvocation,
  type TraceValue,
} from "./liveDebugModel";

/**
 * The spawn seam. The real runner shells the CLI; tests inject a canned trace-JSON runner (no live
 * engine — the CI ide job has no Python). `showPhi` is threaded through so the runner can decide whether
 * to request real values; it is true only for the one run the user asked to reveal, NEVER for a run
 * that "MEFOR Live" starts on save.
 */
export type TraceRunner = (
  samplePath: string,
  cwd: string,
  showPhi: boolean,
) => Promise<LiveTraceEntry[]>;

/**
 * Assemble the `dryrun --trace json` argv. `--show-phi` is appended IFF `showPhi` — the single point
 * where one run's reveal request turns into a real-value request. Pure (no vscode) so it is unit-testable.
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
 * [--show-phi]`. `--show-phi` is present ONLY on a run the user asked to reveal; otherwise the CLI
 * redacts every captured value at the source, so no PHI leaves the Python process.
 */
export const cliTraceRunner: TraceRunner = (samplePath, cwd, showPhi) =>
  runJson<LiveTraceEntry[]>(buildTraceArgs(configDir(), samplePath, showPhi), cwd);

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

// --- v2 inline decorations (per-statement values + hover) ----------------------------------------

/** The redacted placeholder shown in place of any real value on a run that was not revealed. */
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
    : "**Live values** — hidden. Run *MessageFoundry: Reveal Values for One Run* to show them for one run (PHI; synthetic only).";
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
      hover:
        `\`${call}\` is a live, read-only lookup — not evaluated in this offline preview.\n\n` +
        "Preview the feed by stubbing this call's wrapper function (ADR 0010).",
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

/** Ask which of a masked run's messages to reveal; the 0-based index, or undefined if dismissed. */
export type MessagePicker = (messages: MaskedMessage[]) => Promise<number | undefined>;

/** The production {@link MessagePicker}: a quick pick listing file names and dispositions only. */
export const quickPickMessage: MessagePicker = async (messages) => {
  const pick = await vscode.window.showQuickPick(revealPickItems(messages), {
    placeHolder: "Reveal values for which message? One reveal shows one message (PHI; synthetic only).",
  });
  return pick?.index;
};

/**
 * The live-debug controller: owns the on/off state, the chosen sample, the last run's rows + trace and
 * whether that one run was revealed, a debounced save watcher, its CodeLens provider, and the inline
 * decorations. Live is off by default, and every run is masked unless the user asked to reveal that run.
 * The dry-run spawn is injectable so the whole pipeline is testable with canned trace JSON and no engine.
 */
export class LiveDebugController implements vscode.CodeLensProvider, vscode.Disposable {
  private readonly changed = new vscode.EventEmitter<void>();
  readonly onDidChangeCodeLenses = this.changed.event;

  private enabled = false;
  private running = false;
  // Whether the trace in `entries` came from a run the user asked to reveal (ASVS 14.2.6, vault BACKLOG
  // #1187). It describes ONE stored run, not a session preference: each run sets it from its own
  // `showPhi`, so the next run (a save, a re-toggle) stores false and renders masked again.
  private shownRunRevealed = false;
  // A reveal run has started and not yet landed or been superseded. Lets Hide cancel it, and the status
  // item say so, before any value is shown.
  private revealPending = false;
  // The messages of the last MASKED run, and the sample they came from: what a reveal picks among.
  // PHI-free (file-derived names and dispositions). Kept while a revealed run shows, so a second
  // reveal can pick again without a masked run first.
  private maskedMessages: MaskedMessage[] | null = null;
  private maskedFor: string | undefined;
  // Which message the stored revealed run shows; null on a masked run.
  private revealedFocus: RevealFocus | null = null;
  // A reveal is choosing its message (a masked run to list them, or the pick) and has not started its
  // --show-phi run. `revealIntent` is bumped by Hide and Live off, so a choice that finishes after
  // either starts nothing.
  private choosingReveal = false;
  private revealIntent = 0;
  // The in-progress sample pick, shared so a double-click cannot open a second pick (BACKLOG #1187 QA).
  private enabling: Promise<boolean> | undefined;
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

  /**
   * `workspace` defaults to the open folder; a test passes a fixed path, since the integration host
   * opens no folder and every trigger path stops at "no workspace" without one. `pickMessage` is
   * the reveal's which-message question, a quick pick by default; a test answers it directly.
   */
  constructor(
    private readonly runner: TraceRunner = cliTraceRunner,
    private readonly workspace: () => string | undefined = workspaceDir,
    private readonly pickMessage: MessagePicker = quickPickMessage,
  ) {}

  setStatusBar(item: vscode.StatusBarItem): void {
    this.statusBar = item;
    this.updateStatus();
  }

  /** Wire the SEPARATE per-run reveal status item (its own commands — never the Live toggle). */
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

  /** True while the decorations show real values from the one run the user asked to reveal. */
  isShowingValues(): boolean {
    return this.shownRunRevealed;
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

  /**
   * Reflect the shown run in its OWN status item (distinct icon/label from "MEFOR Live"). Hidden, a click
   * reveals ONE run; shown, a click hides. While a reveal runs the click does nothing, so a double-click
   * cannot cancel the reveal it just started (Hide Revealed Values still cancels it). Either way the next
   * run is masked. The item shows only while Live is on, so a click meant for "MEFOR Live: Off" beside it
   * cannot start a reveal.
   */
  private updateRevealStatus(): void {
    const sb = this.revealStatusBar;
    if (!sb) {
      return;
    }
    if (this.enabled) {
      sb.show();
    } else {
      sb.hide();
    }
    if (this.revealPending) {
      sb.text = "$(sync~spin) Values: Revealing…";
      sb.command = undefined;
      sb.tooltip =
        "A run with real values is in progress. Run *MessageFoundry: Hide Revealed Values* to cancel it.";
    } else if (this.choosingReveal) {
      sb.text = "$(sync~spin) Values: Choosing…";
      sb.command = undefined;
      sb.tooltip =
        "Choosing which message to reveal. No real values are shown or fetched yet. Run " +
        "*MessageFoundry: Hide Revealed Values* to cancel.";
    } else if (this.shownRunRevealed) {
      const focus = this.revealedFocus;
      sb.text =
        focus && focus.total > 1
          ? `$(eye) Values: Message ${focus.index + 1} of ${focus.total}`
          : "$(eye) Values: This Run";
      sb.command = "messagefoundry.hideValues";
      sb.tooltip =
        "Live-debug shows real values from ONE message of ONE run (PHI, screenshot-capturable). " +
        "Click to hide them now. " +
        "The next run hides them anyway. Synthetic samples only.";
    } else {
      sb.text = "$(eye-closed) Values: Hidden";
      sb.command = "messagefoundry.revealValuesOnce";
      sb.tooltip =
        "Live-debug inline values are hidden (PHI-safe). Click to re-run once with real values shown. " +
        "The next run hides them again. Synthetic samples only.";
    }
  }

  /** Flip on/off. Turning on picks a synthetic sample (if none) and does a first run; off clears lenses. */
  async toggle(): Promise<void> {
    if (this.enabling) {
      return; // a sample pick is already open; let it finish
    }
    if (this.enabled) {
      this.enabled = false;
      this.error = null;
      this.clearRun();
      return;
    }
    if (await this.enable()) {
      await this.run(false);
    }
  }

  /**
   * Drop the stored run and orphan any run in flight, so a reveal that lands afterwards stores nothing.
   * `rows` go too: on a revealed run their per-message error text is unredacted.
   */
  private clearRun(): void {
    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer); // a pending save run would only repeat the re-run that follows
      this.debounceTimer = undefined;
    }
    this.runToken += 1;
    this.revealIntent += 1; // a reveal still choosing its message starts nothing
    this.running = false;
    this.revealPending = false;
    this.rows = null;
    this.entries = null;
    this.shownRunRevealed = false;
    this.revealedFocus = null;
    this.maskedMessages = null;
    this.updateStatus();
    this.updateRevealStatus();
    this.changed.fire();
    this.refreshDecorations();
  }

  /** Turn Live on, picking a synthetic sample if none is chosen. False (and Live left off) if none is. */
  private enable(): Promise<boolean> {
    this.enabling ??= (async (): Promise<boolean> => {
      let ok = false;
      try {
        this.enabled = true;
        ok = await this.ensureSample();
      } catch (e) {
        void vscode.window.showErrorMessage(
          `MEFOR Live: could not pick a sample: ${e instanceof Error ? e.message : String(e)}`,
        );
      } finally {
        this.enabled = ok;
        this.enabling = undefined;
        this.updateStatus();
        this.updateRevealStatus();
      }
      return ok;
    })();
    return this.enabling;
  }

  /**
   * The user's explicit act for ONE run (ASVS 14.2.6, vault BACKLOG #1187): run the dry-run now with
   * `--show-phi` and show that run's real values. Nothing is armed for later, so the next run (a save,
   * a re-toggle) is masked again. Turns Live on first if it is off, since decorations render only then.
   */
  async revealOnce(): Promise<void> {
    if (this.choosingReveal) {
      return; // one choice at a time: a second would share, and then clear, this one's state
    }
    // Taken before Live is turned on, so a Hide during the sample pick cancels this reveal too.
    const intent = ++this.revealIntent;
    this.choosingReveal = true;
    this.updateRevealStatus();
    let focus: RevealFocus | undefined;
    let cancelledWhileEnabling = false;
    try {
      if ((this.enabling || !this.enabled) && !(await this.enable())) {
        return;
      }
      if (intent !== this.revealIntent) {
        cancelledWhileEnabling = true; // Hide during the sample pick: run masked, after the finally
        return;
      }
      // A save just before the click would otherwise fire a masked run that silently drops this reveal.
      if (this.debounceTimer) {
        clearTimeout(this.debounceTimer);
        this.debounceTimer = undefined;
      }
      focus = await this.chooseRevealFocus(intent);
    } finally {
      this.choosingReveal = false;
      this.updateRevealStatus();
    }
    if (cancelledWhileEnabling) {
      await this.run(false); // Live came on with no run; give it its first, masked one
      return;
    }
    if (focus && intent === this.revealIntent) {
      // A save during the choice armed a debounced masked run; it would supersede this reveal.
      if (this.debounceTimer) {
        clearTimeout(this.debounceTimer);
        this.debounceTimer = undefined;
      }
      await this.run(true, focus);
    }
  }

  /**
   * Which ONE message to reveal (ASVS 14.2.6, vault BACKLOG #1187, ground e; owner ruling R15). Lenses
   * here summarize the whole sample, so nothing on screen singles one out: a one-message sample needs
   * no choice, and a larger one asks, listing the last masked run's messages by file name and
   * disposition. With no masked run of this sample yet, one runs first to learn the list. Undefined
   * means reveal nothing: the pick was dismissed, Live went off, Hide cancelled it, or there was no
   * message.
   */
  private async chooseRevealFocus(intent: number): Promise<RevealFocus | undefined> {
    if (!this.maskedMessages || this.maskedFor !== this.samplePath) {
      await this.run(false);
      if (intent !== this.revealIntent) {
        return undefined; // Hide or Live off cancelled this reveal while its masked run ran
      }
    }
    const messages = this.maskedMessages;
    if (!this.enabled || !messages || messages.length === 0) {
      if (this.enabled) {
        void vscode.window.showInformationMessage(
          this.running
            ? "MEFOR Live: a newer run replaced the one listing the sample's messages. Reveal again when it lands."
            : "MEFOR Live: the masked run gave no message to reveal. Fix the run, then reveal again.",
        );
      }
      return undefined;
    }
    if (messages.length === 1) {
      return { index: 0, total: 1 };
    }
    const index = await this.pickMessage(messages);
    if (index === undefined || intent !== this.revealIntent) {
      return undefined;
    }
    // A save-run that landed during the pick may have re-listed the sample. If its count moved, the
    // index may name another message, so ask again rather than spawn a --show-phi run to find out.
    if (this.maskedMessages?.length !== messages.length) {
      void vscode.window.showInformationMessage(
        "MEFOR Live: the sample's message count changed while you chose, so nothing was revealed. Reveal again.",
      );
      return undefined;
    }
    return { index, total: messages.length };
  }

  /**
   * Hide real values now, or cancel a reveal still running. Drops the stored run (it holds real values)
   * and, when Live is on, re-runs masked so the decorations come back as placeholders. The re-run, not an
   * in-memory mask, is what restores the CLI's own redaction of the per-message error text.
   */
  async hideValues(): Promise<void> {
    if (!this.shownRunRevealed && !this.revealPending && !this.choosingReveal) {
      void vscode.window.showInformationMessage("MEFOR Live: no values are shown, so there is nothing to hide.");
      return;
    }
    this.error = null; // a failed reveal's error text came from the --show-phi CLI, so it goes too
    this.clearRun();
    if (this.enabled && this.samplePath) {
      await this.run(false);
    }
  }

  /** Debounced save hook: re-run only when on, trusted, and the saved file is a config .py module. */
  onSave(doc: vscode.TextDocument): void {
    if (!this.enabled || isExecGated() || doc.languageId !== "python") {
      return;
    }
    if (!isConfigFile(doc.uri.fsPath, this.workspace(), configDir())) {
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
      void this.run(false); // a save-triggered run is never a reveal
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
    const ws = this.workspace();
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

  private async run(showPhi: boolean, focus?: RevealFocus): Promise<void> {
    if (!this.enabled || this.enabling) {
      return; // off, or a sample pick is open: the run that pick leads to is the next one
    }
    const ws = this.workspace();
    if (!ws) {
      return;
    }
    if (!this.samplePath) {
      const ok = await this.ensureSample();
      if (!ok || !this.enabled) {
        return;
      }
    }
    if (isExecGated()) {
      this.error = "workspace not trusted — live-debug disabled until you trust this workspace";
      this.clearRun();
      return;
    }
    // this.samplePath is set by ensureSample above.
    await this.runWith(this.samplePath as string, ws, showPhi, focus);
  }

  /**
   * Run the (injected) trace-runner against a sample and store the result. `showPhi` is this run's own
   * reveal request, masked by default — the ONLY place --show-phi is (conditionally) requested. The
   * stored result records whether IT was revealed, so the next run decides afresh. A per-run token
   * discards a superseded run's late result, so a rapid save-storm always renders the newest run only.
   * A revealed run keeps ONE message: `focus`'s, or the only one when there is no focus. When it
   * cannot tell which, it keeps none and says so (vault BACKLOG #1187, ground e).
   * Public so a test can drive it with a canned runner (no sample-pick, no workspace).
   */
  async runWith(
    samplePath: string,
    cwd: string,
    showPhi = false,
    focus?: RevealFocus,
  ): Promise<void> {
    const token = ++this.runToken;
    this.running = true;
    if (!showPhi) {
      if (this.revealPending) {
        void vscode.window.showInformationMessage(
          "MEFOR Live: a newer run replaced the reveal, so values stay hidden. Reveal again to see them.",
        );
      }
      if (this.shownRunRevealed) {
        // A revealed run ends when the next run STARTS, not when it lands: a slow or superseded masked
        // run must not leave real values painted meanwhile.
        this.entries = null;
        this.rows = null;
        this.error = null; // a failed reveal's error text is unredacted too
        this.shownRunRevealed = false;
        this.revealedFocus = null;
        this.changed.fire();
        this.refreshDecorations();
      }
    }
    this.revealPending = showPhi;
    this.updateStatus();
    this.updateRevealStatus();
    let entries: LiveTraceEntry[] | null = null;
    let rows: LiveDryRunRow[] | null = null;
    let err: string | null = null;
    let unmatched = false; // a revealed run that could not tell which message to keep
    try {
      entries = await this.runner(samplePath, cwd, showPhi);
      if (showPhi) {
        const one = revealedEntry(entries, focus);
        if (one === null) {
          unmatched = true;
          throw new Error(
            focus
              ? "the sample's message count changed since it was listed, so nothing was revealed. Reveal again."
              : `the run held ${entries.length} messages and none was chosen, so nothing was revealed.`,
          );
        }
        entries = [one]; // every other message's values are dropped here, before anything renders
      }
      rows = rowsFromTrace(entries); // inside the try: a skewed trace shape is this run's error
    } catch (e) {
      entries = null;
      rows = null;
      err = e instanceof Error ? e.message : String(e);
    }
    if (token !== this.runToken) {
      return; // superseded by a newer run — drop this stale result
    }
    this.running = false;
    this.revealPending = false;
    this.samplePath = samplePath;
    this.sampleLabel = path.basename(samplePath);
    this.entries = entries;
    // A failed reveal counts as shown too: its error can be the --show-phi CLI's own {"error": ...}
    // text, so Hide must still be able to clear it. A reveal that could not tell which message to
    // keep stored nothing revealed, so it does not count.
    this.shownRunRevealed = showPhi && !unmatched;
    this.revealedFocus = this.shownRunRevealed && entries ? (focus ?? { index: 0, total: 1 }) : null;
    if (!showPhi) {
      // Only a masked run may refresh the reveal pick's list, and only one that produced entries.
      this.maskedMessages = entries ? maskedMessagesOf(entries) : null;
      this.maskedFor = samplePath;
    } else if (unmatched) {
      this.maskedMessages = null; // the list is stale: the next reveal re-lists before it asks
    }
    this.rows = rows;
    this.error = err;
    this.updateStatus();
    this.updateRevealStatus();
    this.changed.fire();
    this.refreshDecorations();
  }

  // --- inline decorations ----------------------------------------------------------------------

  /**
   * Re-apply inline decorations to every visible editor (called after a run, a toggle, or an editor
   * swap). Every one, not only the active one, so a hide or a masked run reaches a split editor too.
   */
  refreshDecorations(): void {
    for (const editor of vscode.window.visibleTextEditors) {
      this.applyDecorations(editor);
    }
  }

  /**
   * Render (or clear) the per-line inline value decorations on `editor`. Clears whenever Live is off,
   * a run errored, there's no trace, or the editor isn't a config module. Otherwise it maps the active
   * module's invocations to redacted-by-default (real only for a revealed run) `after`-text + hover.
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
    // Only a real file editor: a diff's git: side or a compare view shares the fsPath but not the lines.
    if (editor.document.uri.scheme !== "file") {
      clear();
      return;
    }
    if (!isConfigFile(editor.document.uri.fsPath, this.workspace(), configDir())) {
      clear();
      return;
    }
    const invs = invocationsForFile(this.entries, editor.document.uri.fsPath);
    const inline = inlineValuesFor(invs, this.shownRunRevealed);
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
    return buildLiveLenses(
      namedElements(text),
      summarize(this.rows),
      this.shownRunRevealed
        ? revealedLabel(this.sampleLabel ?? "", this.revealedFocus)
        : (this.sampleLabel ?? ""),
      this.shownRunRevealed,
    );
  }

  provideCodeLenses(document: vscode.TextDocument): vscode.CodeLens[] {
    if (!this.enabled) {
      return [];
    }
    if (!isConfigFile(document.uri.fsPath, this.workspace(), configDir())) {
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
 * Wire live-debug into the extension: two left status-bar items — the "MEFOR Live" toggle (off by
 * default) and the SEPARATE per-run reveal item (hidden by default) — their commands, this lane's own CodeLens
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

  // The per-run reveal is its OWN status item, independent of "MEFOR Live". Its command flips between
  // revealValuesOnce and hideValues with the shown run, and it shows only while Live is on (both set in
  // updateRevealStatus).
  const revealBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 49);
  controller.setRevealStatusBar(revealBar);

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
      "messagefoundry.revealValuesOnce",
      () => void controller.revealOnce(),
    ),
    vscode.commands.registerCommand("messagefoundry.hideValues", () => void controller.hideValues()),
    vscode.languages.registerCodeLensProvider({ language: "python" }, controller),
    vscode.workspace.onDidSaveTextDocument((doc) => controller.onSave(doc)),
    vscode.window.onDidChangeActiveTextEditor(() => controller.refreshDecorations()),
  );
  return controller;
}
