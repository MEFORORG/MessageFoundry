// The Steps view editor (ADR 0076 §2 phase 2b + phase 3 / BACKLOG #222). A `CustomTextEditorProvider`
// over a Handler `.py` that renders it as a Corepoint-style ordered, nested typed Steps view:
// action / lookup / control / send rows with parameter forms, and in-place read-only `code` rows for
// anything outside the bounded grammar (the §4 degradation ladder — a line is never hidden).
//
// It gets its structure by shelling `messagefoundry lens parse <module.py> --json` (the L2 engine CLI) —
// it NEVER parses Python in TypeScript. On a whole-file parse refusal (or an exec-gated / unreadable
// module) it steps aside to the plain text editor with a notice (the InterSystems fallback guardrail).
//
// EDITING (phase 3, ADR 0076 §5): recognized action/lookup/send rows expose ENABLED param inputs;
// `code`/`control` rows stay read-only (they are not regenerable from a template — visibly disabled). On
// a field change the webview posts the edit; the provider shells `messagefoundry lens rewrite - --edit
// <json>` (the live buffer piped via stdin, NOT the on-disk file) and applies the byte-stable result
// THROUGH the document via a `WorkspaceEdit` (so undo/redo + hot-exit work — never an out-of-band file
// write). One edit at a time + an update-loop guard (EditLoopGuard); the projection still refreshes on
// SAVE only. "Reopen With: Python" is always available. Entry is OPT-IN — a "Reopen in Steps view"
// CodeLens on each `@handler` + a command — NOT the default editor for `.py`.
//
// Live values (#92 / ADR 0072 / BACKLOG #225): the rows are decorated with the per-line values a traced
// dry-run computes. The lens acquires them via a SECOND `dryrun --trace json` it shells against a chosen
// synthetic sample (reusing the Test Bench's sample-selection pattern) — NOT by reaching into the shared
// LiveDebugController's private trace state (which would couple to internals and only work while live-debug
// is toggled on). Values are PHI: the lens's trace call NEVER passes `--show-phi` (redacted at the CLI),
// the fold renders the same `▸ ⋯` placeholder liveDebug uses, and nothing is persisted (the JSON is
// consumed over stdout). With no sample picked — or a trace that yields nothing / errors — the rows carry
// no value and the toolbar's redacted placeholder stands; a live-value failure is never surfaced as an error.
// The trace reads the module FROM DISK, so while the buffer is DIRTY (an unsaved edit shifted rows off
// disk) the lens SKIPS live values rather than mapping stale disk line numbers onto shifted rows (BACKLOG
// #225) — they re-attach on the next save, when disk == buffer.
import * as fs from "node:fs";
import * as path from "node:path";
import * as vscode from "vscode";
import {
  configDir,
  isExecGated,
  messageSetsDir,
  runJson,
  runJsonWithStdin,
  runWithStdin,
  workspaceDir,
} from "./cli";
import { invocationsForFile, type LiveTraceEntry } from "./liveDebug";
import {
  EditLoopGuard,
  INSERT_ACTION_LABELS,
  REDACTED_LIVE_VALUE,
  TOOLBAR_INSERT_DEFAULTS,
  buildDeleteRequest,
  buildEditRequest,
  buildHandlerViewModels,
  buildLensTraceArgs,
  buildMoveRequest,
  buildMoveToRequest,
  buildPasteRequest,
  buildToolbarInsertRequest,
  drainEdits,
  escapeHtml,
  mergeLiveValues,
  parseRewriteResult,
  renderHandlersHtml,
  renderStepsContextMenuHtml,
  shouldAttachLiveValues,
  shouldFallBackToText,
  traceRowValues,
  type EditMessage,
  type HandlerViewModel,
  type LensParseResult,
  type LiveInlineValue,
  type RowKind,
  type StructuralRequest,
} from "./stepsModel";
import {
  loadSchema,
  loadStructures,
  segmentsOf,
  type Hl7Schema,
  type Hl7Structures,
} from "./hl7schema";
import { buildSegmentScope, sampleSegments } from "./hl7scope";
import { pickHl7Path, type PickScope } from "./hl7Picker";

/** Debounce (ms) before re-parsing after the underlying document changes in a split text view. */
const RERENDER_DEBOUNCE_MS = 250;

function nonce(): string {
  let s = "";
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  for (let i = 0; i < 24; i++) {
    s += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return s;
}

export class StepsEditorProvider implements vscode.CustomTextEditorProvider {
  static readonly viewType = "messagefoundry.stepsEditor";

  // The synthetic sample the live-value trace runs against — shared across every open lens editor so a
  // pick is remembered (the "reuse the last-picked sample" affordance). Never a real-PHI file: the picker
  // defaults to messageSetsDir and the trace is redacted regardless.
  private samplePath: string | undefined;
  private sampleLabel: string | undefined;

  // The extension version (from package.json), shown in the toolbar so a preview install is verifiable at
  // a glance (and it bumps per change, so a reinstall is visibly distinct — no more "did the new vsix load?").
  // extensionUri locates media/stepsWebview.js — the webview script is loaded as an EXTERNAL file (via
  // asWebviewUri), NOT inline, so it can never hit the inline-script/CSP class of silent load failures.
  // The bundled HL7 schema (ADR 0104 §2.3 field picker) + the optional message-structure/verified artifact
  // (§2.3 P2/P3; `undefined` until that build lands). Loaded once — pure in-memory data, no per-pick I/O.
  private readonly schema: Hl7Schema | undefined;
  private readonly structures: Hl7Structures | undefined;
  // ADR 0104 §2.3 P2: handler name -> its recognized message type, stashed by render() from the lens parse
  // (a projection of the current parse, never persisted state). Read by scopeFor to rank the picker.
  private handlerTypes = new Map<
    string,
    { acceptsTypes?: string[]; inferredType?: { code?: string; trigger?: string } }
  >();

  constructor(
    private readonly version: string,
    private readonly extensionUri: vscode.Uri,
  ) {
    this.schema = loadSchema(extensionUri.fsPath);
    this.structures = loadStructures(extensionUri.fsPath);
  }

  /** The segment ranking/scope for a handler's recognized message type (ADR 0104 §2.3 P2). Undefined when
   *  there is no schema bundle or the type is unresolvable → the picker offers the generic, unscoped
   *  segment list. Reads the (synthetic, PHI-safe) sample so its Z-segments / segments union in. */
  private scopeFor(handler: string): PickScope | undefined {
    if (!this.schema) {
      return undefined;
    }
    const t = this.handlerTypes.get(handler);
    let sample: string[] = [];
    if (this.samplePath) {
      try {
        sample = sampleSegments(fs.readFileSync(this.samplePath, "utf8"));
      } catch {
        sample = []; // no/unreadable sample → no sample union, still scoped by type
      }
    }
    return buildSegmentScope(
      segmentsOf(this.schema),
      this.structures,
      t?.acceptsTypes,
      t?.inferredType,
      sample,
    );
  }

  /**
   * Acquire the redacted-by-default live values for the open handler via a SECOND traced dry-run
   * (`dryrun --trace json`, ADR 0072) against the chosen synthetic sample, folded to per-row inline
   * values (liveDebug.invocationsForFile → traceRowValues). PHI guardrails: it NEVER passes `--show-phi`
   * (the CLI redacts every value), never reveals (reveal off), and never persists (the JSON is consumed
   * over stdout). It NEVER throws — no sample, an exec-gated workspace, or a failed/empty trace all yield
   * `[]`, so the rows simply carry no value and the toolbar's redacted placeholder stands.
   */
  private async liveValuesFor(fsPath: string, ws: string | undefined): Promise<LiveInlineValue[]> {
    if (!this.samplePath || !ws || isExecGated()) {
      return [];
    }
    try {
      const entries = await runJson<LiveTraceEntry[]>(
        buildLensTraceArgs(configDir(), this.samplePath),
        ws,
      );
      // Reveal OFF, always — the lens never un-redacts and the argv never carried `--show-phi`, so every
      // captured value came back as the CLI's "REDACTED" sentinel and folds to the `▸ ⋯` placeholder.
      return traceRowValues(invocationsForFile(entries, fsPath), false);
    } catch {
      return []; // a live-value failure is never an error — the redacted placeholder stands
    }
  }

  /**
   * Pick a synthetic HL7 sample for the live-value trace — the Test Bench's selection pattern (an open
   * dialog defaulting to messageSetsDir, `.hl7`-filtered), not a new sample manager. Returns the chosen
   * path (also stored for reuse) or undefined if cancelled / no workspace.
   */
  private async pickSample(): Promise<string | undefined> {
    const ws = workspaceDir();
    if (!ws) {
      void vscode.window.showInformationMessage("MessageFoundry: open a workspace folder first.");
      return undefined;
    }
    const dir = messageSetsDir();
    const abs = path.isAbsolute(dir) ? dir : path.join(ws, dir);
    const picks = await vscode.window.showOpenDialog({
      canSelectMany: false,
      canSelectFiles: true,
      canSelectFolders: false,
      defaultUri: vscode.Uri.file(abs),
      openLabel: "Use for Live Values",
      filters: { "HL7 messages": ["hl7"], "All files": ["*"] },
    });
    if (!picks || picks.length === 0) {
      return undefined;
    }
    this.samplePath = picks[0].fsPath;
    this.sampleLabel = path.basename(this.samplePath);
    return this.samplePath;
  }

  resolveCustomTextEditor(
    document: vscode.TextDocument,
    panel: vscode.WebviewPanel,
    _token: vscode.CancellationToken,
  ): void {
    // localResourceRoots must include media/ so the webview can load the external stepsWebview.js script.
    panel.webview.options = {
      enableScripts: true,
      localResourceRoots: [vscode.Uri.joinPath(this.extensionUri, "media")],
    };
    let debounce: ReturnType<typeof setTimeout> | undefined;
    let disposed = false;
    // Handshake: the webview posts a `ping` the instant its script starts. If a render sets the html but no
    // ping arrives, the script never initialized (blocked / threw at load, e.g. a double acquireVsCodeApi) —
    // the provider surfaces that itself, so a silently-dead toolbar can never masquerade as "just disabled".
    let sawAlive = false;
    // One edit at a time + the webview↔document update-loop guard (ADR 0076 §5).
    const guard = new EditLoopGuard();

    // Reopen the same resource with the built-in text editor (the §4 degradation fallback).
    const fallBackToText = (reason: string): void => {
      void vscode.window.showInformationMessage(reason);
      void vscode.commands.executeCommand("vscode.openWith", document.uri, "default");
      panel.webview.html = noticeHtml(reason);
    };

    const render = async (): Promise<void> => {
      const ws = workspaceDir();
      // Project the LIVE buffer (piped over stdin as `lens parse -`), NOT the on-disk file: after a
      // structural edit's WorkspaceEdit the buffer is dirty (buffer != disk), and the row coordinates
      // must describe what the user actually sees. Parsing the same `source` we then slice for the
      // view-models keeps every row's `expectSrc` aligned with the projected buffer (F7). Static parse —
      // never imports/executes the module (a module whose top level would raise still parses, §5).
      const source = document.getText();
      let parse: LensParseResult | null = null;
      let error: string | null = null;
      try {
        parse = await runJsonWithStdin<LensParseResult>(["lens", "parse", "-"], source, ws);
      } catch (e) {
        error = e instanceof Error ? e.message : String(e);
      }
      if (disposed) {
        return;
      }
      const decision = shouldFallBackToText(parse, error);
      if (decision.fallback) {
        fallBackToText(decision.reason ?? "MessageFoundry: opening as text.");
        return;
      }
      // parse is non-null here (shouldFallBackToText returned fallback:false only for a real handler set).
      const handlers = buildHandlerViewModels(parse as LensParseResult, source);
      // ADR 0104 §2.3 P2: stash each handler's recognized message type for the field picker's scope (a
      // projection of THIS parse — not persisted state).
      this.handlerTypes = new Map(
        (parse as LensParseResult).handlers.map((h) => [
          h.handler,
          { acceptsTypes: h.accepts_types, inferredType: h.inferred_type },
        ]),
      );
      // Live values come from a SECOND `dryrun --trace` that reads the module FROM DISK, but the rows
      // above are projected from the LIVE buffer. While the buffer is dirty (an unsaved structural edit
      // shifted rows relative to disk — or any unsaved change made buffer != disk) the disk trace's line
      // numbers describe the PRE-edit file, so attaching them by line containment would land a marker on
      // the WRONG row (BACKLOG #225). A dry-run can't reflect an unsaved buffer, so SKIP the trace
      // entirely until the next save realigns disk == buffer — the toolbar's redacted placeholder stands
      // meanwhile. (This is the same "sync on save" reason the projection itself refreshes on save only.)
      const inline = shouldAttachLiveValues(document.isDirty)
        ? await this.liveValuesFor(document.uri.fsPath, ws)
        : [];
      if (disposed) {
        return;
      }
      for (const h of handlers) {
        mergeLiveValues(h.rows, inline);
      }
      const scriptUri = panel.webview.asWebviewUri(
        vscode.Uri.joinPath(this.extensionUri, "media", "stepsWebview.js"),
      );
      panel.webview.html = pageHtml(panel.webview, handlers, this.sampleLabel, this.version, scriptUri);
      // Arm the handshake: if the freshly-loaded script doesn't ping within 3s, it failed to initialize.
      sawAlive = false;
      setTimeout(() => {
        if (!disposed && !sawAlive) {
          void vscode.window.showErrorMessage(
            "MessageFoundry Steps: the view's script did not initialize (its toolbar/selection won't work). " +
              "Reopen the file as Steps; if it persists, use “View as Code”.",
          );
        }
      }, 3000);
    };

    // Apply one recognized-row param edit (ADR 0076 §5): shell `lens rewrite` on the LIVE buffer (piped
    // via stdin, never the on-disk file), then splice the byte-stable result back THROUGH the document
    // via a WorkspaceEdit — keeping undo/redo + hot-exit intact (never an out-of-band write). The edit
    // carries the row's PROJECTION-TIME source (`msg.expectSrc`, from `data-expect-src`) as `expect_src`,
    // so the engine compares the row as it was PROJECTED against the live buffer's row at that line range
    // and REFUSES a stale coordinate (F7). We must NOT recompute expect_src from the same live buffer we
    // send as stdin — that compares the buffer against itself and the guard always passes (the defect).
    const applyOne = async (msg: EditMessage): Promise<void> => {
      const spec = buildEditRequest(msg);
      const res = await runWithStdin(
        ["lens", "rewrite", "-", "--edit", JSON.stringify(spec)],
        document.getText(),
        workspaceDir(),
      );
      if (disposed) {
        return;
      }
      const outcome = parseRewriteResult(res);
      if (outcome.source === undefined) {
        void vscode.window.showErrorMessage(
          `MessageFoundry: could not apply the edit — ${outcome.error ?? "lens rewrite failed"}`,
        );
        await render(); // revert the optimistic webview change to the true projection
        return;
      }
      if (outcome.source === document.getText()) {
        return; // no-op (e.g. the value was re-typed unchanged) — nothing to write
      }
      const edit = new vscode.WorkspaceEdit();
      const fullRange = new vscode.Range(
        document.positionAt(0),
        document.positionAt(document.getText().length),
      );
      edit.replace(document.uri, fullRange, outcome.source);
      await vscode.workspace.applyEdit(edit);
    };

    // One edit at a time. A change that races an in-flight rewrite is NOT dropped — it is queued and
    // applied once the current one settles, so the user's typed intent survives a rapid second edit (F5).
    // The drain is delegated to the pure `drainEdits` so an UNEXPECTED applyEdit rejection (NOT the
    // CLI-refusal path, which `applyOne` handles inline) releases the slot AND keeps draining the queue
    // rather than stranding a pending second edit until the user types again.
    const applyEdit = (msg: EditMessage): Promise<void> =>
      drainEdits(guard, msg, applyOne, (err) => {
        void vscode.window.showErrorMessage(
          `MessageFoundry: could not apply the edit — ${err instanceof Error ? err.message : String(err)}`,
        );
        void render(); // revert the optimistic webview change to the true projection
      });

    // Apply a STRUCTURAL op (insert/delete/move). Unlike a param edit these change the file's line count,
    // so every row coordinate the webview holds becomes stale — the op must run ALONE (never batched with
    // a queued param edit on stale coords) and force a full re-projection afterwards (ADR 0076 §5 v2). It
    // claims the single edit slot; if a param edit is mid-flight it declines (retry) rather than racing.
    // Returns whether it APPLIED a change (a WorkspaceEdit was written) — false for a guard-busy decline, a
    // refusal, a no-op, or an error. The paste path uses this to show a success toast only on a real change.
    const applyStructural = async (spec: StructuralRequest): Promise<boolean> => {
      if (!guard.beginEdit()) {
        void vscode.window.showInformationMessage(
          "MessageFoundry: an edit is in progress — try again in a moment.",
        );
        return false;
      }
      let applied = false;
      try {
        const res = await runWithStdin(
          ["lens", "rewrite", "-", "--edit", JSON.stringify(spec)],
          document.getText(),
          workspaceDir(),
        );
        if (disposed) {
          return false;
        }
        const outcome = parseRewriteResult(res);
        if (outcome.source === undefined) {
          void vscode.window.showErrorMessage(
            `MessageFoundry: could not apply the change — ${outcome.error ?? "lens rewrite failed"}`,
          );
          return false; // finally releases the slot; the webview already shows the (unchanged) true view
        }
        if (outcome.source !== document.getText()) {
          const edit = new vscode.WorkspaceEdit();
          const fullRange = new vscode.Range(
            document.positionAt(0),
            document.positionAt(document.getText().length),
          );
          edit.replace(document.uri, fullRange, outcome.source);
          await vscode.workspace.applyEdit(edit); // one WorkspaceEdit → undo/redo + hot-exit intact
          applied = true;
        }
      } catch (err) {
        void vscode.window.showErrorMessage(
          `MessageFoundry: could not apply the change — ${err instanceof Error ? err.message : String(err)}`,
        );
      } finally {
        // A structural op rebuilds the whole webview against NEW coordinates, so any param edit that was
        // queued while it held the slot references stale PRE-op coordinates. DROP that queue before
        // releasing the slot — never let the next drain apply it against shifted rows (the orphaned-queue
        // hazard; without this the queued edit survives re-projection and is later applied on stale coords,
        // ADR 0076 §5 v2). clearPending precedes endEdit so nothing can drain in between.
        guard.clearPending();
        guard.endEdit();
      }
      if (disposed) {
        return applied;
      }
      // FORCE a full re-projection against the NEW buffer — parse it fresh + rebuild the webview (never
      // reuse the stale coordinates). This is the load-bearing v2 rule for structural ops.
      await render();
      return applied;
    };

    // Apply a PICKED HL7 path (ADR 0104 §2.3). A pick is a `set_params` value swap — **coordinate-preserving**,
    // NOT a structural op — so it goes through the SAME `applyOne` splice a typed edit uses (no new artifact,
    // no new .py execution path) AND must uphold the same F5 guarantee: a typed edit that queued while the
    // pick's `lens rewrite` was in flight is **drained** (`takePending`), never dropped (a `clearPending` here
    // would silently discard a still-valid edit, since the pick did not shift any row's coordinates). It
    // claims the single edit slot around the pick + drain, then ALWAYS re-projects — a picked value has no
    // optimistic DOM value to rely on (unlike a typed edit). The F7 `expect_src` stale guard rides through
    // `applyOne` unchanged: a coordinate shifted by a raced edit is REFUSED, not mis-spliced.
    const applyPickedEdit = async (msg: EditMessage): Promise<void> => {
      if (!guard.beginEdit()) {
        void vscode.window.showInformationMessage(
          "MessageFoundry: an edit is in progress — try again in a moment.",
        );
        return;
      }
      try {
        let current: EditMessage | undefined = msg;
        while (current) {
          await applyOne(current); // applyOne handles its own error + revert-render
          current = guard.takePending(); // drain a raced typed edit (F5) — NEVER clearPending (that drops it)
        }
      } finally {
        guard.endEdit();
      }
      if (disposed) {
        return;
      }
      await render(); // reflect the picked value (no optimistic DOM value) + any drained edits
    };

    // Undo / redo the document's edit stack. Every Steps edit lands there as a WorkspaceEdit (see applyOne
    // / applyStructural), so VS Code's own undo/redo already covers them — these buttons just surface it
    // inside the webview, where Ctrl+Z doesn't reach the document. Runs as a lone op behind the edit guard
    // so it never races an in-flight rewrite, then re-projects the (now-changed) LIVE buffer. VS Code owns
    // the stack, so with nothing to undo/redo the command is a harmless no-op.
    const applyUndoRedo = async (command: "undo" | "redo"): Promise<void> => {
      if (!guard.beginEdit()) {
        void vscode.window.showInformationMessage(
          "MessageFoundry: an edit is in progress — try again in a moment.",
        );
        return;
      }
      try {
        await vscode.commands.executeCommand(command);
      } catch (err) {
        void vscode.window.showErrorMessage(
          `MessageFoundry: could not ${command} — ${err instanceof Error ? err.message : String(err)}`,
        );
      } finally {
        guard.clearPending();
        guard.endEdit();
      }
      if (disposed) {
        return;
      }
      await render();
    };

    panel.webview.onDidReceiveMessage(
      (m: {
        command?: string;
        line?: number;
        handler?: string;
        lineStart?: number;
        lineEnd?: number;
        name?: string;
        value?: string;
        direction?: "up" | "down";
        toLineStart?: number;
        toLineEnd?: number;
        toPosition?: "before" | "after";
        toSuite?: string;
        expectSrc?: string;
        action?: string;
        kind?: string;
        block?: string;
        text?: string;
        level?: string;
        position?: string;
        mode?: string;
      }) => {
        if (m?.command === "test") {
          // Reuse the existing Test Bench (dry-run this workspace's config — no engine, no sending).
          void vscode.commands.executeCommand("messagefoundry.openTestBench");
        } else if (m?.command === "pickSample") {
          // Pick a synthetic sample for the live-value trace, then re-project so its values decorate rows.
          void (async () => {
            const picked = await this.pickSample();
            if (picked && !disposed) {
              await render();
            }
          })();
        } else if (m?.command === "openText") {
          void vscode.commands.executeCommand("vscode.openWith", document.uri, "default");
        } else if (m?.command === "undo" || m?.command === "redo") {
          void applyUndoRedo(m.command);
        } else if (m?.command === "codeLocked") {
          // The user tried to drag a read-only Code step (the degradation-ladder passthrough): the lens
          // won't restructure code it doesn't model, so point them at the text editor (View as Code).
          void vscode.window.showInformationMessage(
            "MessageFoundry: a Code step is read-only in the Steps view — open “View as Code” to move or edit it.",
          );
        } else if (m?.command === "openSource" && typeof m.line === "number") {
          // Jump to the underlying .py line (reuses the shared open-at-line command).
          void vscode.commands.executeCommand(
            "messagefoundry.openSource",
            document.uri.fsPath,
            m.line,
          );
        } else if (
          m?.command === "edit" &&
          typeof m.handler === "string" &&
          typeof m.lineStart === "number" &&
          typeof m.lineEnd === "number" &&
          typeof m.name === "string" &&
          typeof m.value === "string" &&
          typeof m.expectSrc === "string"
        ) {
          void applyEdit({
            command: "edit",
            handler: m.handler,
            lineStart: m.lineStart,
            lineEnd: m.lineEnd,
            name: m.name,
            value: m.value,
            // The row's PROJECTION-TIME source, echoed from `data-expect-src` — the F7 stale-coordinate
            // guard input. Never recomputed from the live buffer here (that made the guard tautological).
            expectSrc: m.expectSrc,
          });
        } else if (
          m?.command === "pickPath" &&
          typeof m.handler === "string" &&
          typeof m.lineStart === "number" &&
          typeof m.lineEnd === "number" &&
          typeof m.name === "string" &&
          typeof m.expectSrc === "string"
        ) {
          // ADR 0104 §2.3: run the native cascading field picker OUTSIDE the edit guard (a modal must not
          // hold the single edit slot — mirrors pickSample), then apply the chosen path through the SAME
          // set_params splice. No schema bundle → nothing to pick (silent no-op). Capture the narrowed
          // fields in consts so their types survive into the async closure.
          const handler = m.handler;
          const lineStart = m.lineStart;
          const lineEnd = m.lineEnd;
          const name = m.name;
          const expectSrc = m.expectSrc;
          const mode = m.mode === "segment" ? "segment" : "path";
          const seed = typeof m.value === "string" ? m.value : "";
          void (async () => {
            if (!this.schema || disposed) {
              return;
            }
            const picked = await pickHl7Path(this.schema, {
              mode,
              scope: this.scopeFor(handler),
              verified: this.structures?.verified,
              seed,
            });
            if (picked === undefined || disposed) {
              return; // cancelled — no write
            }
            await applyPickedEdit({
              command: "edit",
              handler,
              lineStart,
              lineEnd,
              name,
              value: picked,
              expectSrc,
            });
          })();
        } else if (
          m?.command === "deleteRow" &&
          typeof m.handler === "string" &&
          typeof m.lineStart === "number" &&
          typeof m.lineEnd === "number"
        ) {
          void applyStructural(
            buildDeleteRequest({
              command: "deleteRow",
              handler: m.handler,
              lineStart: m.lineStart,
              lineEnd: m.lineEnd,
              expectSrc: m.expectSrc,
            }),
          );
        } else if (
          m?.command === "moveRow" &&
          typeof m.handler === "string" &&
          typeof m.lineStart === "number" &&
          typeof m.lineEnd === "number" &&
          (m.direction === "up" || m.direction === "down")
        ) {
          void applyStructural(
            buildMoveRequest({
              command: "moveRow",
              handler: m.handler,
              lineStart: m.lineStart,
              lineEnd: m.lineEnd,
              direction: m.direction,
              expectSrc: m.expectSrc,
            }),
          );
        } else if (
          m?.command === "moveTo" &&
          typeof m.handler === "string" &&
          typeof m.lineStart === "number" &&
          typeof m.lineEnd === "number" &&
          typeof m.toLineStart === "number" &&
          (m.toPosition === "before" || m.toPosition === "after")
        ) {
          // Drag-and-drop reorder: move the dragged block to the chosen anchor position — possibly in a
          // DIFFERENT suite (cross-suite move, the block re-indents). Like every structural op it runs alone
          // and forces a full re-projection; `toSuite` is the destination stale-guard and a stale drop is
          // refused by the engine (LensRewriteError → error toast + re-projection, unchanged).
          void applyStructural(
            buildMoveToRequest({
              command: "moveTo",
              handler: m.handler,
              lineStart: m.lineStart,
              lineEnd: m.lineEnd,
              toLineStart: m.toLineStart,
              toLineEnd: m.toLineEnd,
              toPosition: m.toPosition,
              toSuite: m.toSuite,
              expectSrc: m.expectSrc,
            }),
          );
        } else if (
          m?.command === "insertToolbar" &&
          typeof m.action === "string" &&
          // Guard the action against the known toolbar catalog (the INSERTABLE_ACTIONS keys) before acting —
          // inbound webview data is untrusted (a `params` template is only defined for these).
          Object.prototype.hasOwnProperty.call(TOOLBAR_INSERT_DEFAULTS, m.action) &&
          typeof m.handler === "string" &&
          typeof m.lineStart === "number" &&
          typeof m.lineEnd === "number" &&
          typeof m.kind === "string" &&
          // An OPTIONAL explicit position (the right-click "Insert before"/"Insert after") — validated
          // against the two legal values before it reaches the engine (inbound webview data is untrusted).
          // Absent (the toolbar Add) → buildToolbarInsertRequest derives it from the anchor kind.
          (m.position === undefined || m.position === "before" || m.position === "after")
        ) {
          // Insert a DEFAULT-param template at the currently SELECTED row (no InputBox prompts). The
          // position is either the explicit context-menu choice or derived from the anchor's kind (send →
          // before the return, else after) inside buildToolbarInsertRequest, which reuses the byte-stable
          // `lens rewrite` path via applyStructural.
          void applyStructural(
            buildToolbarInsertRequest(
              {
                handler: m.handler,
                lineStart: m.lineStart,
                lineEnd: m.lineEnd,
                expectSrc: m.expectSrc,
                kind: m.kind as RowKind,
              },
              m.action,
              m.position as "before" | "after" | undefined,
            ),
          );
        } else if (
          (m?.command === "copyBlock" || m?.command === "cutInfo") &&
          typeof m.text === "string"
        ) {
          // Copy/Cut feedback — the block source lives in the webview clipboard (vscode.setState); the
          // provider only surfaces the toast. Validate the text (inbound webview data is untrusted).
          void vscode.window.showInformationMessage(m.text);
        } else if (m?.command === "stepsDiag" && typeof m.text === "string") {
          // Steps webview self-diagnostic. The `ping` is the handshake — the script started, so it did NOT
          // die at load; record it and stay silent. An `error` (uncaught script error) or `info` (load-state
          // report) surfaces as a toast, so a problem invisible in the webview iframe console becomes visible.
          if (m.level === "ping") {
            sawAlive = true;
          } else {
            const msg = `MessageFoundry Steps: ${m.text.slice(0, 300)}`;
            if (m.level === "error") {
              void vscode.window.showErrorMessage(msg);
            } else {
              void vscode.window.showInformationMessage(msg);
            }
          }
        } else if (
          m?.command === "paste" &&
          typeof m.handler === "string" &&
          typeof m.lineStart === "number" &&
          typeof m.lineEnd === "number" &&
          typeof m.kind === "string" &&
          typeof m.block === "string" &&
          m.block !== ""
        ) {
          // Paste the captured block at the selected anchor via the byte-stable `lens rewrite` path
          // (applyStructural). A refusal surfaces the engine LensRewriteError as an error toast with ZERO
          // change; on a real change we show the "Pasted …" toast the webview supplied.
          const pasteText =
            typeof m.text === "string" ? m.text : "MessageFoundry: pasted the steps.";
          void applyStructural(
            buildPasteRequest(
              {
                handler: m.handler,
                lineStart: m.lineStart,
                lineEnd: m.lineEnd,
                expectSrc: m.expectSrc,
                kind: m.kind as RowKind,
              },
              { source: m.block, nesting: 0, kind: m.kind as RowKind, lineCount: 0, label: "" },
            ),
          ).then((ok) => {
            if (ok && !disposed) {
              void vscode.window.showInformationMessage(pasteText);
            }
          });
        }
      },
    );

    // The lens is READ-ONLY and refreshes ON SAVE only (ADR 0076 §5 "sync on save" guardrail): `lens parse`
    // reads the file from disk, so re-projecting on every keystroke would slice the current (dirty) buffer
    // against line ranges computed from stale disk content, and re-shell Python per keystroke. Saving makes
    // disk == buffer, so the projection stays aligned. Debounced to coalesce rapid saves.
    const sub = vscode.workspace.onDidSaveTextDocument((saved) => {
      if (saved.uri.toString() !== document.uri.toString()) {
        return;
      }
      // Don't re-project while our own edit's WorkspaceEdit is still applying — that is the webview↔
      // document update loop the guard exists to break (ADR 0076 §5). A save after the edit settles
      // re-renders normally.
      if (!guard.shouldReactToDocumentChange()) {
        return;
      }
      if (debounce) {
        clearTimeout(debounce);
      }
      debounce = setTimeout(() => {
        debounce = undefined;
        void render();
      }, RERENDER_DEBOUNCE_MS);
    });
    panel.onDidDispose(() => {
      disposed = true;
      sub.dispose();
      if (debounce) {
        clearTimeout(debounce);
      }
    });

    void render();
  }
}

/** A minimal notice page shown momentarily while the resource reopens as text (fallback path). */
function noticeHtml(reason: string): string {
  return (
    '<!DOCTYPE html><html><head><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'"></head>' +
    '<body style="font-family:sans-serif;padding:1rem">' +
    reason.replace(/[<>&]/g, (c) => (c === "<" ? "&lt;" : c === ">" ? "&gt;" : "&amp;")) +
    "</body></html>"
  );
}

/** Wrap the pure rows body in the CSP/nonce page shell + the in-editor toolbar (AWS Workflow Studio pattern). */
function pageHtml(
  webview: vscode.Webview,
  handlers: HandlerViewModel[],
  sampleLabel: string | undefined,
  version: string,
  scriptUri: vscode.Uri,
): string {
  const n = nonce();
  const body = renderHandlersHtml(handlers);
  // The insert-toolbar dropdown: a leading "[select item]" placeholder (value ""), then one option per
  // insertable action, built from the single-source-of-truth INSERT_ACTION_LABELS (same friendly labels
  // the rows show). Labels are static, but escape defensively per the CSP/injection rule.
  const insertOptions = [`<option value="">[select item]</option>`]
    .concat(
      INSERT_ACTION_LABELS.map(
        (o) => `<option value="${escapeHtml(o.value)}">${escapeHtml(o.label)}</option>`,
      ),
    )
    .join("");
  const sampleBtn = sampleLabel
    ? `Sample: ${escapeHtml(sampleLabel)}`
    : "Pick Sample…";
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta http-equiv="Content-Security-Policy"
        content="default-src 'none'; style-src ${webview.cspSource} 'unsafe-inline'; script-src ${webview.cspSource} 'nonce-${n}';" />
  <style>
    body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); padding: 0 12px 16px; }
    .bar { padding: 10px 0; position: sticky; top: 0; z-index: 1; background: var(--vscode-editor-background);
           display: flex; gap: 8px; align-items: center; border-bottom: 1px solid var(--vscode-panel-border); }
    .bar .sep { width: 1px; align-self: stretch; margin: 2px 4px; background: var(--vscode-panel-border); }
    #stepsFilter { font-family: inherit; font-size: 13px; color: var(--vscode-input-foreground);
                   background: var(--vscode-input-background); border: 1px solid var(--vscode-input-border, var(--vscode-panel-border));
                   border-radius: 2px; padding: 3px 6px; min-width: 180px; }
    /* Pick Sample opens the right cluster (preview → verify → escape): Test and View-as-Code follow it. */
    #pickSample { margin-left: auto; }
    /* "View as Code" is the inverse of the title bar's "View as Steps" toggle — carry it at secondary/link
       weight so the two surfaces don't both shout the mode switch. */
    button.link { background: transparent; color: var(--vscode-textLink-foreground); padding: 4px 6px; }
    button.link:hover { background: rgba(127,127,127,0.15); text-decoration: underline; }
    button { font-family: inherit; color: var(--vscode-button-foreground); background: var(--vscode-button-background);
             border: none; padding: 4px 10px; cursor: pointer; border-radius: 2px; font-size: 13px; }
    button:hover { background: var(--vscode-button-hoverBackground); }
    /* Insert toolbar: a native <select> (built-in type-ahead) + a subtle-green Add. No visible label
       (aria-label only). The green is a SUBTLE left-accent border, not the button fill: keeping the
       guaranteed-legible button.background/button.foreground pair means the label stays readable in
       every theme (light/dark/high-contrast), while charts.green only tints the accent. VS Code has no
       green button token, so a fill-green would force a foreground that only suits one theme (D2). */
    select#insertAction { font-family: inherit; font-size: 13px; color: var(--vscode-dropdown-foreground);
             background: var(--vscode-dropdown-background); border: 1px solid var(--vscode-dropdown-border, var(--vscode-panel-border));
             border-radius: 2px; padding: 3px 6px; max-width: 220px; }
    button#addAction { background: var(--vscode-button-background); color: var(--vscode-button-foreground);
             font-weight: 600; border-left: 3px solid var(--vscode-charts-green, #3fb950); border-radius: 0 2px 2px 0; }
    button#addAction:hover:enabled { background: var(--vscode-button-hoverBackground); }
    button#addAction:disabled { cursor: default; opacity: 0.5; border-left-color: var(--vscode-disabledForeground, rgba(127,127,127,0.5)); }
    /* Extension version — a glanceable install check: it bumps per change, so a fresh vsix reads as a new number. */
    .bar .ver { align-self: center; color: var(--vscode-descriptionForeground);
                font-size: 11px; font-variant-numeric: tabular-nums; }
    button.jump { color: var(--vscode-textLink-foreground); background: transparent; padding: 0 4px; font-size: 11px; }
    button.jump:hover { background: rgba(127,127,127,0.15); text-decoration: underline; }
    section.handler { margin: 10px 0 18px; }
    section.handler > h2 { font-size: 14px; font-weight: 600; margin: 8px 0; display: flex; align-items: baseline; gap: 8px; }
    ol.rows { list-style: none; margin: 0; padding: 0; }
    li.row { border: 1px solid var(--vscode-panel-border); border-radius: 4px; margin: 6px 0; padding: 6px 8px;
             background: var(--vscode-editorWidget-background, rgba(127,127,127,0.06)); cursor: pointer; }
    /* The single SELECTED row (the toolbar Add's insert location) — a themed highlight that reads in both
       themes. A row is keyboard-focusable (tabindex); the outline follows its selection. */
    li.row.selected { background: var(--vscode-list-activeSelectionBackground);
             color: var(--vscode-list-activeSelectionForeground); outline: 1px solid var(--vscode-focusBorder); outline-offset: -1px; }
    li.row:focus { outline: 1px solid var(--vscode-focusBorder); outline-offset: -1px; }
    /* Drag-and-drop reorder (ADR 0076, cross-suite #222): a movable row/block is draggable and can land at
       top level OR inside any control body. The scope is shown BEFORE release by three indicators — an
       insertion bar drawn at the LANDING depth, a scope pill naming the landing suite, and a left-border
       tint on every row of the landing suite — so the classic for-header ambiguity is chosen explicitly. */
    li.row[draggable="true"] { cursor: grab; }
    li.row.dragging { opacity: 0.45; }
    /* Every row of the landing suite gets a subtle left border while hovering a drop — the whole target
       scope is visible at a glance (kept thin so it never shifts layout). */
    li.row.drop-scope { box-shadow: inset 3px 0 0 0 var(--vscode-focusBorder); }
    /* The insertion bar: a thin accent line drawn INDENTED to the landing depth (its left offset differs
       for "first inside the loop" vs "after the loop at outer", the two for-header interpretations). */
    .insertion-bar { position: fixed; height: 2px; background: var(--vscode-focusBorder);
             pointer-events: none; z-index: 10; border-radius: 1px; }
    /* The scope pill rides near the pointer, naming the landing suite ("top level" / "inside for each …"). */
    .scope-pill { position: fixed; pointer-events: none; z-index: 11; font-size: 11px; line-height: 1.4;
             padding: 1px 6px; border-radius: 3px; white-space: nowrap;
             color: var(--vscode-editorHoverWidget-foreground, var(--vscode-foreground));
             background: var(--vscode-editorHoverWidget-background, var(--vscode-editorWidget-background));
             border: 1px solid var(--vscode-editorHoverWidget-border, var(--vscode-panel-border)); }
    li.row .row-head { display: flex; align-items: baseline; gap: 8px; flex-wrap: wrap; }
    li.row .kind { text-transform: uppercase; font-size: 10px; letter-spacing: 0.04em; font-weight: 700;
                   color: var(--vscode-descriptionForeground); border: 1px solid var(--vscode-panel-border);
                   border-radius: 3px; padding: 0 4px; }
    li.row .title { font-weight: 600; }
    li.row .subtitle { color: var(--vscode-descriptionForeground); font-size: 12px; font-family: var(--vscode-editor-font-family, monospace); }
    li.row .badge { font-size: 10px; color: var(--vscode-editorWarning-foreground); border: 1px solid var(--vscode-editorWarning-foreground);
                    border-radius: 3px; padding: 0 4px; text-transform: uppercase; }
    li.row .live { margin-left: 4px; color: var(--vscode-editorCodeLens-foreground); font-style: italic; font-size: 12px; }
    /* Per-row structural affordances (move/add/delete) — shown only on recognized rows. */
    li.row .row-actions { margin-left: auto; display: inline-flex; gap: 2px; }
    li.row .row-actions button.rowop { color: var(--vscode-icon-foreground, var(--vscode-foreground));
                    background: transparent; padding: 0 5px; font-size: 12px; line-height: 18px; border-radius: 3px; }
    li.row .row-actions button.rowop:hover:enabled { background: rgba(127,127,127,0.18); }
    /* An ↑/↓ at a suite edge (first/last sibling) is greyed — the reorder there is a no-op, so don't offer it. */
    li.row .row-actions button.rowop:disabled { opacity: 0.3; cursor: default; }
    /* Row accent by kind. */
    li.row-control { border-left: 3px solid var(--vscode-charts-blue, #3794ff); }
    li.row-send { border-left: 3px solid var(--vscode-charts-green, #3fb950); }
    li.row-lookup { border-left: 3px solid var(--vscode-charts-purple, #b180d7); }
    li.row-action { border-left: 3px solid var(--vscode-charts-orange, #d18616); }
    li.row-code { border-left: 3px solid var(--vscode-descriptionForeground); }
    .params { display: flex; flex-wrap: wrap; gap: 8px 14px; margin-top: 6px; }
    .params .field { display: flex; flex-direction: column; gap: 2px; min-width: 120px; }
    .params .field label { font-size: 11px; color: var(--vscode-descriptionForeground); }
    .params .field input { font-family: var(--vscode-editor-font-family, monospace); font-size: 12px;
                           color: var(--vscode-foreground); background: var(--vscode-input-background);
                           border: 1px solid var(--vscode-input-border, var(--vscode-panel-border)); border-radius: 2px;
                           padding: 2px 6px; }
    /* An editable (recognized-row) field is focusable; a read-only field (code/control, or an argument
       the lens can't round-trip) is visibly muted. */
    .params .field input:disabled { opacity: 0.6; cursor: default; }
    .params .field input.edit:focus { outline: 1px solid var(--vscode-focusBorder); }
    /* ADR 0104 §2.3 field picker: the ⋮ button sits beside its input (the input keeps flexing, so free-text
       stays first-class). Only a pickable path/segment slot gets the .edit-row wrapper. */
    .params .field .edit-row { display: flex; align-items: stretch; gap: 3px; }
    .params .field .edit-row input.edit { flex: 1 1 auto; min-width: 0; }
    button.pickpath { flex: 0 0 auto; cursor: pointer; border: 1px solid var(--vscode-input-border, var(--vscode-panel-border));
                      border-radius: 2px; background: var(--vscode-input-background);
                      color: var(--vscode-icon-foreground, var(--vscode-foreground)); padding: 0 7px; font-size: 13px; line-height: 1; }
    button.pickpath:hover { background: rgba(127,127,127,0.18); }
    button.pickpath:focus { outline: 1px solid var(--vscode-focusBorder); }
    /* An empty editable field hints [blank] (a placeholder, never a value) so a freshly-inserted
       template reads as "fill me in" without the analyst erasing a literal token. Muted + italic so it
       never reads as real content. */
    .params .field input::placeholder { color: var(--vscode-input-placeholderForeground, var(--vscode-descriptionForeground));
                           opacity: 1; font-style: italic; }
    pre.code { margin: 6px 0 0; padding: 6px 8px; background: var(--vscode-textCodeBlock-background, rgba(127,127,127,0.1));
               border: 1px solid var(--vscode-panel-border); border-radius: 3px; overflow: auto;
               font-family: var(--vscode-editor-font-family, monospace); font-size: 12px; white-space: pre; }
    .empty { color: var(--vscode-descriptionForeground); }
    /* Hover tooltips anchored ABOVE the control (the native title attribute shows below the cursor
       after a delay, overlapping the next row). Applied via data-tip; form controls (input/select)
       can't host a ::after, so they're wrapped in a span[data-tip]. */
    [data-tip] { position: relative; }
    [data-tip]:hover::after {
      content: attr(data-tip); position: absolute; left: 50%; bottom: calc(100% + 8px);
      transform: translateX(-50%); z-index: 100; width: max-content; max-width: 280px;
      white-space: normal; text-align: left; padding: 4px 8px; font-size: 12px; line-height: 1.4;
      border-radius: 4px; color: var(--vscode-editorHoverWidget-foreground, var(--vscode-foreground));
      background: var(--vscode-editorHoverWidget-background, var(--vscode-editorWidget-background));
      border: 1px solid var(--vscode-editorHoverWidget-border, var(--vscode-panel-border));
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.36); pointer-events: none; }
    [data-tip]:hover::before {
      content: ""; position: absolute; left: 50%; bottom: calc(100% + 3px); transform: translateX(-50%);
      border: 5px solid transparent; z-index: 100; pointer-events: none;
      border-top-color: var(--vscode-editorHoverWidget-border, var(--vscode-panel-border)); }
    span[data-tip] { display: inline-flex; align-items: center; }
    /* The toolbar is flush against the webview's top edge, so an above-tooltip there would be clipped
       off-screen. Flip only the toolbar's tooltips below (still fully visible); row tooltips stay above
       so they never cover the next step. */
    .bar [data-tip]:hover::after { top: calc(100% + 8px); bottom: auto; }
    .bar [data-tip]:hover::before { top: calc(100% + 3px); bottom: auto;
      border-top-color: transparent;
      border-bottom-color: var(--vscode-editorHoverWidget-border, var(--vscode-panel-border)); }
    /* Right-click ROW context menu (BACKLOG #222 follow-up). A single hidden template the script positions
       at the pointer; submenus reveal on hover / keyboard focus-within (no JS show/hide of submenus).
       Uses VS Code's menu.* tokens with editorWidget/list fallbacks so it reads in every theme. */
    .ctx-menu { position: fixed; z-index: 30; min-width: 168px; padding: 4px; border-radius: 5px;
                background: var(--vscode-menu-background, var(--vscode-editorWidget-background));
                color: var(--vscode-menu-foreground, var(--vscode-foreground));
                border: 1px solid var(--vscode-menu-border, var(--vscode-editorWidget-border, var(--vscode-panel-border)));
                box-shadow: 0 2px 10px rgba(0,0,0,0.36); font-size: 13px; }
    .ctx-menu[hidden] { display: none; }
    .ctx-sub { position: relative; }
    .ctx-item { display: flex; align-items: center; justify-content: space-between; gap: 16px; width: 100%;
                box-sizing: border-box; text-align: left; background: transparent; color: inherit; border: none;
                padding: 3px 8px; font-family: inherit; font-size: 13px; line-height: 20px; border-radius: 3px;
                cursor: pointer; white-space: nowrap; }
    .ctx-item:hover:not(:disabled), .ctx-item:focus:not(:disabled) {
                background: var(--vscode-menu-selectionBackground, var(--vscode-list-activeSelectionBackground));
                color: var(--vscode-menu-selectionForeground, var(--vscode-list-activeSelectionForeground));
                outline: none; }
    .ctx-item:disabled { opacity: 0.4; cursor: default; }
    .ctx-arrow { opacity: 0.75; font-size: 11px; margin-left: auto; }
    .ctx-sep { height: 1px; margin: 4px 2px; background: var(--vscode-menu-separatorBackground, var(--vscode-panel-border)); }
    /* Submenu: hidden until the SCRIPT opens it (JS-controlled + mutually exclusive — see openSubmenu in
       stepsWebview.js). NOT CSS :hover/:focus-within, which let a FOCUSED parent and a HOVERED sibling both
       open and overlap (two submenus stacked). Opens to the right, flipping left when the root menu sits
       near the viewport's right edge; a disabled parent (Insert after on a send row) never opens. */
    .ctx-submenu { position: absolute; top: -5px; left: 100%; min-width: 152px; display: none; }
    .ctx-sub.ctx-open > .ctx-submenu { display: block; }
    .ctx-sub.ctx-disabled > .ctx-submenu { display: none !important; }
    .ctx-root.ctx-flip-sub .ctx-submenu { left: auto; right: 100%; }
  </style>
</head>
<body>
  <div class="bar">
    <span data-tip="Filter the visible steps by text — segment, field path, action, or Send target"><input id="stepsFilter" type="search" placeholder="Filter steps…" /></span>
    <span class="sep"></span>
    <span data-tip="Choose an action to insert at the selected row"><select id="insertAction" aria-label="Insert action">${insertOptions}</select></span>
    <button id="addAction" disabled data-tip="Insert the chosen action at the selected row">Add</button>
    <button id="pickSample" data-tip="Pick a synthetic HL7 sample to preview live per-row values (redacted by default — never real PHI)">${sampleBtn}</button>
    <button id="test" data-tip="Dry-run messages through this config in the Test Bench (no engine, no sending)">Test</button>
    <button id="openText" class="link" data-tip="Switch to the code (text) view of this Handler. Switch back with the ‘View as Steps’ button in the editor toolbar.">View as Code</button>
    <span class="ver" data-tip="MessageFoundry extension version (bumps with each change — a preview-install check)">v${escapeHtml(version)}</span>
  </div>
  <!-- Undo/Redo (Ctrl+Z/Y) and Copy/Cut/Paste (Ctrl+C/X/V) are keyboard-served — the redundant toolbar
       buttons were removed to keep the bar lean. A right-click ROW context menu (below) now surfaces the
       structural verbs (Insert before/after, Delete, Move up/down); copy/cut/paste stay keyboard-only. -->
  ${body}
  <!-- The single, hidden row context-menu template (server-rendered so the CSP webview never innerHTMLs
       markup + the insert catalog stays the one INSERT_ACTION_LABELS source of truth). The script shows,
       positions, greys, and dismisses it, then posts the SAME insert/delete/move messages the toolbar and
       row buttons post — no second execution path. -->
  ${renderStepsContextMenuHtml()}
  <script nonce="${n}" src="${scriptUri}"></script>
</body>
</html>`;
}

/** Register the Steps view: the custom editor provider and the opt-in command. */
export function registerSteps(context: vscode.ExtensionContext): void {
  context.subscriptions.push(
    vscode.window.registerCustomEditorProvider(
      StepsEditorProvider.viewType,
      new StepsEditorProvider(
        String(context.extension.packageJSON.version ?? "?"),
        context.extensionUri,
      ),
      { webviewOptions: { retainContextWhenHidden: true }, supportsMultipleEditorsPerDocument: false },
    ),
    vscode.commands.registerCommand("messagefoundry.openSteps", (uri?: vscode.Uri) => {
      const target = uri ?? vscode.window.activeTextEditor?.document.uri;
      if (!target) {
        void vscode.window.showInformationMessage("MessageFoundry: open a Handler .py file first.");
        return;
      }
      void vscode.commands.executeCommand(
        "vscode.openWith",
        target,
        StepsEditorProvider.viewType,
      );
    }),
  );
}
