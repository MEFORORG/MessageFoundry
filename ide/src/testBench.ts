// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Test Bench: load a message set, dry-run it through the config (no sending), show a results table,
// and a Before/After view per message (side-by-side or above/below) with an HL7 segment/field-aware
// diff — inserted/deleted segments are aligned so they don't cascade false changes, and changed
// fields are highlighted inline (see hl7diff.ts) — plus a Coverage/Profiling view per message (which
// Router/Handler lines ran + per-line time, from `dryrun --trace json`, see traceView.ts) and optional
// step-through under the debugger.
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as vscode from "vscode";
import { configDir, messageSetsDir, pythonPath, runJson, workspaceDir } from "./cli";
import { hexdump } from "./hexdump";
import { diffMessages } from "./hl7diff";
import { buildTraceDetail, type TraceDetail, type TraceEntry } from "./traceView";
import { testBenchScript } from "./testBenchWebview";
import { openChannel, postToWebview } from "./webviewMessaging";
import {
  judgeCollectionRun,
  type CaseRerun,
  type CaseRunDetail,
  type TestCase,
  type TestCollection,
} from "./testCollections";

// Saved regression collections (BACKLOG #168, ADR 0121) live in machine-local workspaceState — NEVER a
// repo file, and NEVER globalState (Settings-Sync-eligible → could carry PHI off-box). Keyed map.
const COLLECTIONS_KEY = "messagefoundry.testBench.collections";

interface Delivery {
  to: string;
  payload: string;
}

interface DryRunRow {
  source: string;
  inbound: string;
  disposition: string;
  message_type: string | null;
  control_id: string | null;
  summary: string | null;
  handlers: string[];
  deliveries: Delivery[];
  error: string | null;
  raw: string;
  path?: string; // source file path (from the CLI) — used to launch the debugger
}

type Incoming =
  | { command: "load" }
  | { command: "diff"; index: number }
  | { command: "trace"; index: number }
  | { command: "debug"; index: number }
  | { command: "hex"; index: number }
  | { command: "listCollections" }
  | { command: "saveCollection" }
  | { command: "runCollection"; name: string }
  | { command: "caseDetail"; run: number; index: number }
  | { command: "deleteCollection"; name: string };

function esc(s: string): string {
  // Escape quotes too, not just &<>: these dry-run-derived values (source/disposition, themselves
  // influenced by the HL7 under test) land inside double-quoted HTML attributes (e.g.
  // class="disp ${esc(...)}"), so an unescaped " would break out of the attribute.
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function defaultMessagesUri(): vscode.Uri | undefined {
  const ws = workspaceDir();
  if (!ws) {
    return undefined;
  }
  const dir = messageSetsDir();
  return vscode.Uri.file(path.isAbsolute(dir) ? dir : path.join(ws, dir));
}

export class TestBench {
  private panel: vscode.WebviewPanel | undefined;
  private rows: DryRunRow[] = [];
  private pickPaths: string[] = []; // the files last loaded — re-run under --trace on demand
  private traces: TraceEntry[] | null = null; // lazily fetched, aligned 1:1 with `rows` by index
  // The last collection run's per-case differences and errors. They stay here, in the host, and one
  // case's go to the webview only when that case is clicked (ASVS 14.2.6, BACKLOG #2437). `id` names
  // the run, so a click on a run the view no longer shows reveals nothing.
  private lastRun: { id: number; details: CaseRunDetail[] } | null = null;
  private runSeq = 0;

  constructor(private readonly context: vscode.ExtensionContext) {}

  open(): void {
    if (this.panel) {
      this.panel.reveal();
      return;
    }
    this.panel = vscode.window.createWebviewPanel(
      "messagefoundry.testBench",
      "MessageFoundry Test Bench",
      vscode.ViewColumn.Active,
      { enableScripts: true, retainContextWhenHidden: true },
    );
    this.panel.onDidDispose(
      () => {
        this.panel = undefined;
        this.lastRun = null;
      },
      null,
      this.context.subscriptions,
    );
    this.panel.webview.onDidReceiveMessage((m: Incoming) => void this.onMessage(m));
    this.render();
  }

  private async onMessage(m: Incoming): Promise<void> {
    if (m.command === "load") {
      await this.loadSet();
    } else if (m.command === "diff") {
      await this.showDiff(m.index);
    } else if (m.command === "trace") {
      await this.showTrace(m.index);
    } else if (m.command === "debug") {
      await this.debugRow(m.index);
    } else if (m.command === "hex") {
      await this.showHex(m.index);
    } else if (m.command === "listCollections") {
      await this.postCollections();
    } else if (m.command === "saveCollection") {
      await this.saveCollection();
    } else if (m.command === "runCollection") {
      await this.runCollection(m.name);
    } else if (m.command === "caseDetail") {
      await this.showCaseDetail(m.run, m.index);
    } else if (m.command === "deleteCollection") {
      await this.deleteCollection(m.name);
    }
  }

  // ---- Saved regression collections (BACKLOG #168, ADR 0121) -----------------------------------
  // All persistence is machine-local workspaceState (not globalState — that is Settings-Sync-eligible
  // and could carry PHI off-box). Case bodies are PHI; authors are steered to synthetic cases.

  private loadCollections(): Record<string, TestCollection> {
    return this.context.workspaceState.get<Record<string, TestCollection>>(COLLECTIONS_KEY, {});
  }

  private async storeCollections(map: Record<string, TestCollection>): Promise<void> {
    await this.context.workspaceState.update(COLLECTIONS_KEY, map);
  }

  /** Post the current collection list (name + case count only — bodies stay in the host) to the webview. */
  private async postCollections(): Promise<void> {
    if (!this.panel) {
      return;
    }
    const map = this.loadCollections();
    const items = Object.values(map)
      .map((c) => ({ name: c.name, cases: c.cases.length }))
      .sort((a, b) => a.name.localeCompare(b.name));
    await postToWebview(this.panel.webview, { type: "collections", items });
  }

  /** Snapshot the currently-loaded rows as a named collection: input `raw` + the current deliveries. */
  private async saveCollection(): Promise<void> {
    if (this.rows.length === 0) {
      void vscode.window.showInformationMessage(
        "MessageFoundry: load a message set first, then save it as a collection.",
      );
      return;
    }
    const name = (
      await vscode.window.showInputBox({
        prompt: "Name this regression collection",
        placeHolder: "e.g. ADT smoke suite",
        validateInput: (v) => (v.trim() ? undefined : "Enter a name"),
      })
    )?.trim();
    if (!name) {
      return;
    }
    const map = this.loadCollections();
    if (map[name]) {
      const overwrite = await vscode.window.showWarningMessage(
        `A collection named "${name}" already exists. Overwrite it?`,
        { modal: true },
        "Overwrite",
      );
      if (overwrite !== "Overwrite") {
        return;
      }
    }
    const cases: TestCase[] = this.rows.map((r) => ({
      name: r.source,
      input: r.raw,
      expected: r.deliveries.map((d) => ({ to: d.to, payload: d.payload })),
    }));
    map[name] = { name, cases };
    await this.storeCollections(map);
    await this.postCollections();
    void vscode.window.showInformationMessage(
      `MessageFoundry: saved collection "${name}" (${cases.length} case${cases.length === 1 ? "" : "s"}).`,
    );
  }

  private async deleteCollection(name: string): Promise<void> {
    const map = this.loadCollections();
    if (!map[name]) {
      return;
    }
    const ok = await vscode.window.showWarningMessage(
      `Delete regression collection "${name}"?`,
      { modal: true },
      "Delete",
    );
    if (ok !== "Delete") {
      return;
    }
    delete map[name];
    await this.storeCollections(map);
    await this.postCollections();
  }

  /**
   * Rerun a saved collection and flag pass/fail per case. The `dryrun` CLI takes only file paths, so
   * each case's stored input is materialized to a FRESH per-run temp dir, dry-run (`--show-phi`), and
   * the temp dir is deleted in `finally` — transient PHI, always cleaned. Cases align to rows by the
   * unique temp basename the CLI echoes back in `row.path` (robust to a case that yields no row).
   */
  private async runCollection(name: string): Promise<void> {
    if (!this.panel) {
      return;
    }
    const coll = this.loadCollections()[name];
    const cwd = workspaceDir();
    if (!coll || !cwd) {
      return;
    }
    let tmpDir: string | undefined;
    try {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "mefor-testbench-"));
      const files = coll.cases.map((c, i) => {
        const file = path.join(tmpDir as string, `case_${String(i).padStart(4, "0")}.hl7`);
        fs.writeFileSync(file, c.input, "utf8");
        return file;
      });
      const rows = await runJson<DryRunRow[]>(
        ["dryrun", "--config", configDir(), "--show-phi", "--messages", ...files],
        cwd,
      );
      const byBase = new Map<string, DryRunRow>();
      for (const row of rows) {
        if (row.path) {
          byBase.set(path.basename(row.path), row);
        }
      }
      const reruns = coll.cases.map((_c, i): CaseRerun | undefined => {
        const row = byBase.get(`case_${String(i).padStart(4, "0")}.hl7`);
        return row
          ? {
              disposition: row.disposition,
              error: row.error ?? null,
              deliveries: row.deliveries.map((d) => ({ to: d.to, payload: d.payload })),
            }
          : undefined;
      });
      const run = judgeCollectionRun(coll.cases, reruns);
      const id = ++this.runSeq;
      this.lastRun = { id, details: run.details };
      // Pass or fail per case, and nothing else: each case's field values and error text stay in
      // `lastRun` until that one case is clicked (showCaseDetail).
      await postToWebview(this.panel.webview, {
        type: "collectionRun",
        name,
        run: id,
        passed: run.passed,
        total: run.summaries.length,
        results: run.summaries,
      });
    } catch (e) {
      void vscode.window.showErrorMessage(`MessageFoundry: collection run failed — ${String(e)}`);
    } finally {
      if (tmpDir) {
        // Best-effort cleanup of the transient PHI temp dir; never let a cleanup error mask the run.
        try {
          fs.rmSync(tmpDir, { recursive: true, force: true });
        } catch {
          /* OS temp reaping bounds any residue */
        }
      }
    }
  }

  /**
   * Post ONE case's differences and error, for the case the developer clicked in the run view. The
   * webview never holds another case's values, because the host never sends them (ASVS 14.2.6,
   * BACKLOG #2437). A click naming a run other than the last one, or no case in it, posts nothing.
   */
  private async showCaseDetail(run: unknown, index: unknown): Promise<void> {
    const last = this.lastRun;
    if (!this.panel || !last || run !== last.id || !Number.isSafeInteger(index)) {
      return;
    }
    const detail = last.details[index as number];
    if (!detail) {
      return;
    }
    await postToWebview(this.panel.webview, {
      type: "caseDetail",
      run: last.id,
      index,
      error: detail.error,
      deliveries: detail.deliveries,
    });
  }

  /**
   * UTF-8 byte hex pane over the received body (BACKLOG #84, ADR 0119). `row.raw` is the string the
   * dry-run already decoded (UTF-8/replace), so this dumps ITS UTF-8 bytes — not the original wire
   * bytes, and not an mfb64/base64 decode. Computed host-side by the pure `hexdump()` (mirroring the
   * diff/trace panes) and posted; the render is capped and lives only in the webview (no disk, no log).
   */
  private async showHex(index: number): Promise<void> {
    const row = this.rows[index];
    if (!row || !this.panel) {
      return;
    }
    await postToWebview(this.panel.webview, {
      type: "hex",
      source: row.source,
      dump: hexdump(row.raw),
    });
  }

  private async loadSet(): Promise<void> {
    const cwd = workspaceDir();
    if (!cwd) {
      void vscode.window.showErrorMessage("MessageFoundry: open a workspace folder first.");
      return;
    }
    const picks = await vscode.window.showOpenDialog({
      canSelectMany: true, // one or more files; a file may hold many messages
      canSelectFiles: true,
      canSelectFolders: false,
      defaultUri: defaultMessagesUri(),
      openLabel: "Load Message Set",
      filters: { "HL7 messages": ["hl7"], "All files": ["*"] },
    });
    if (!picks || picks.length === 0) {
      return;
    }
    const pickPaths = picks.map((p) => p.fsPath);
    try {
      // One CLI call for all picks (the CLI batches files/folders, splits multi-message files, and
      // returns a `path` per row).
      this.rows = await runJson<DryRunRow[]>(
        // --show-phi: the Test Bench renders the developer's own test messages, so it needs the
        // full bodies the CLI redacts by default.
        ["dryrun", "--config", configDir(), "--show-phi", "--messages", ...pickPaths],
        cwd,
      );
    } catch (e) {
      void vscode.window.showErrorMessage(`MessageFoundry: dry-run failed — ${String(e)}`);
      return;
    }
    // Remember the picks so Coverage/Profiling can re-run the SAME set under --trace (aligned by
    // index); drop any stale trace cache from a previous load.
    this.pickPaths = pickPaths;
    this.traces = null;
    this.render();
  }

  /**
   * Fetch (once, then cache) the traced dry-run of the loaded set. `dryrun --trace json` iterates the
   * SAME expanded message list as the plain dry-run, in the same order, so `traces[i]` lines up with
   * `rows[i]`. No `--show-phi`: Coverage/Profiling need only line numbers + timings, never PHI values.
   */
  private async ensureTraces(): Promise<TraceEntry[] | null> {
    if (this.traces) {
      return this.traces;
    }
    const cwd = workspaceDir();
    if (!cwd || this.pickPaths.length === 0) {
      return null;
    }
    try {
      this.traces = await runJson<TraceEntry[]>(
        ["dryrun", "--config", configDir(), "--messages", ...this.pickPaths, "--trace", "json"],
        cwd,
      );
    } catch (e) {
      void vscode.window.showErrorMessage(`MessageFoundry: trace failed — ${String(e)}`);
      return null;
    }
    return this.traces;
  }

  private async showTrace(index: number): Promise<void> {
    if (!this.panel) {
      return;
    }
    const traces = await this.ensureTraces();
    const entry = traces?.[index];
    if (!entry) {
      void vscode.window.showInformationMessage("MessageFoundry: no trace available for this message.");
      return;
    }
    // fs-backed, per-detail cached source reader (the config .py is code, not PHI). Injected into the
    // pure builder so traceView.ts stays testable without a filesystem.
    const srcCache = new Map<string, string | null>();
    const readSource = (file: string | null): string | null => {
      if (!file) {
        return null;
      }
      if (!srcCache.has(file)) {
        try {
          srcCache.set(file, fs.readFileSync(file, "utf8"));
        } catch {
          srcCache.set(file, null);
        }
      }
      return srcCache.get(file) ?? null;
    };
    const detail: TraceDetail = buildTraceDetail(entry, readSource);
    await postToWebview(this.panel.webview, { type: "trace", detail });
  }

  private async showDiff(index: number): Promise<void> {
    const row = this.rows[index];
    if (!row || !this.panel) {
      return;
    }
    let after: string;
    let to: string;
    if (row.deliveries.length === 0) {
      to = row.disposition;
      after = `(no message would be sent — ${row.disposition}${row.error ? `: ${row.error}` : ""})`;
    } else {
      let delivery = row.deliveries[0];
      if (row.deliveries.length > 1) {
        const pick = await vscode.window.showQuickPick(
          row.deliveries.map((d, i) => ({ label: d.to, description: `output ${i + 1}`, i })),
          { placeHolder: "Which outbound delivery?" },
        );
        if (!pick) {
          return;
        }
        delivery = row.deliveries[pick.i];
      }
      to = delivery.to;
      after = delivery.payload;
    }
    // Compute the segment/field-aware diff here (pure, in the extension host) and post the aligned
    // result; the webview only renders it. diffMessages tolerates \r / \n / \r\n itself.
    await postToWebview(this.panel.webview, {
      type: "detail",
      source: row.source,
      to,
      diff: diffMessages(row.raw, after),
    });
  }

  private async debugRow(index: number): Promise<void> {
    const row = this.rows[index];
    const folder = vscode.workspace.workspaceFolders?.[0];
    if (!row?.path || !folder) {
      return;
    }
    await vscode.debug.startDebugging(folder, {
      name: `MEFOR dry-run: ${row.source}`,
      type: "debugpy",
      request: "launch",
      module: "messagefoundry",
      args: ["dryrun", "--config", configDir(), "--show-phi", "--messages", row.path],
      console: "integratedTerminal",
      justMyCode: false, // step into the config modules (Router/Handler)
      python: pythonPath(),
    });
  }

  private render(): void {
    if (this.panel) {
      this.panel.webview.html = this.html(this.panel.webview);
    }
  }

  private rowsHtml(): string {
    return this.rows
      .map((r, i) => {
        const routed = r.handlers.length ? esc(r.handlers.join(", ")) : "—";
        const outs = r.deliveries.length ? esc(r.deliveries.map((d) => d.to).join(", ")) : "—";
        return `<tr>
          <td>${esc(r.source)}</td>
          <td>${esc(r.message_type ?? "")}</td>
          <td><span class="disp ${esc(r.disposition)}">${esc(r.disposition)}</span></td>
          <td>${routed}</td>
          <td>${outs}</td>
          <td class="actions">
            <button data-act="diff" data-i="${i}">Before/After</button>
            <button data-act="hex" data-i="${i}">Hex</button>
            <button data-act="trace" data-i="${i}">Coverage / Profile</button>
            <button data-act="debug" data-i="${i}">Debug</button>
          </td>
        </tr>`;
      })
      .join("");
  }

  private html(webview: vscode.Webview): string {
    const { nonce: n, token } = openChannel(webview);
    const body = this.rows.length
      ? `<table>
          <thead><tr><th>Message</th><th>Type</th><th>Disposition</th><th>Routed →</th><th>Outputs</th><th></th></tr></thead>
          <tbody>${this.rowsHtml()}</tbody>
        </table>`
      : `<p class="empty">No messages loaded. Click <b>Load Message Set</b> to dry-run <code>.hl7</code>
         files (or a folder) against this workspace's config — nothing is sent. A file may contain
         many messages; each is run separately.</p>`;

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta http-equiv="Content-Security-Policy"
        content="default-src 'none'; style-src ${webview.cspSource} 'unsafe-inline'; script-src 'nonce-${n}';" />
  <style>
    body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); padding: 0 12px; }
    .bar { padding: 10px 0; position: sticky; top: 0; background: var(--vscode-editor-background); display: flex; gap: 8px; }
    button { font-family: inherit; color: var(--vscode-button-foreground); background: var(--vscode-button-background);
             border: none; padding: 4px 10px; cursor: pointer; border-radius: 2px; }
    button:hover { background: var(--vscode-button-hoverBackground); }
    table { border-collapse: collapse; width: 100%; }
    th, td { text-align: left; padding: 4px 8px; border-bottom: 1px solid var(--vscode-panel-border); font-size: 13px; }
    th { color: var(--vscode-descriptionForeground); font-weight: 600; }
    td.actions button { padding: 2px 8px; margin-right: 6px; }
    .empty { color: var(--vscode-descriptionForeground); max-width: 660px; }
    .disp { padding: 1px 6px; border-radius: 3px; font-size: 12px; }
    .disp.received { color: var(--vscode-testing-iconPassed, #3fb950); }
    .disp.unrouted { color: var(--vscode-list-warningForeground, #d29922); }
    .disp.filtered { color: var(--vscode-descriptionForeground); }
    .disp.error { color: var(--vscode-testing-iconFailed, #f85149); }
    #detail { display: none; }
    #detail h3 { margin: 8px 0; font-size: 13px; font-weight: 600; }
    .pane { margin-bottom: 14px; }
    .pane .lbl { color: var(--vscode-descriptionForeground); font-size: 12px; margin-bottom: 2px; }
    .pane pre { margin: 0; padding: 8px; background: var(--vscode-textCodeBlock-background, rgba(127,127,127,0.1));
                border: 1px solid var(--vscode-panel-border); border-radius: 3px; overflow: auto;
                font-family: var(--vscode-editor-font-family, monospace); font-size: 12px; }
    /* HL7-aware diff: whole-line background for an inserted/deleted segment, inline field spans for a
       changed field within an otherwise-matched segment (red on the before pane, green on the after). */
    .pane pre div.ln { white-space: pre-wrap; word-break: break-word; }
    .pane pre div.ln-ins { background: var(--vscode-diffEditor-insertedLineBackground, rgba(63,185,80,0.12)); }
    .pane pre div.ln-del { background: var(--vscode-diffEditor-removedLineBackground, rgba(248,81,73,0.12)); }
    .pane pre div.gap { opacity: 0.35; }
    .pane pre span.ins { background: var(--vscode-diffEditor-insertedTextBackground, rgba(63,185,80,0.35)); border-radius: 2px; }
    .pane pre span.del { background: var(--vscode-diffEditor-removedTextBackground, rgba(248,81,73,0.35)); border-radius: 2px; }
    .panes.sbs { display: flex; gap: 12px; align-items: flex-start; }
    .panes.sbs .pane { flex: 1 1 0; min-width: 0; margin-bottom: 0; }
    /* Coverage / Profiling (traceView.ts). */
    .inv { margin-bottom: 18px; }
    .inv h4 { margin: 6px 0; font-size: 13px; font-weight: 600; display: flex; align-items: baseline; gap: 8px; }
    .inv h4 .kind { color: var(--vscode-descriptionForeground); font-weight: 600; text-transform: uppercase; font-size: 11px; }
    .inv .meta { color: var(--vscode-descriptionForeground); font-size: 12px; font-weight: normal; }
    .note { color: var(--vscode-descriptionForeground); font-size: 12px; margin: 4px 0; }
    /* Executed-line coverage: exact green for lines that ran, red for executable lines that didn't,
       dim for non-executable (def/decorator/comment/blank) context. */
    pre.cov { margin: 0; padding: 6px 0; background: var(--vscode-textCodeBlock-background, rgba(127,127,127,0.1));
              border: 1px solid var(--vscode-panel-border); border-radius: 3px; overflow: auto;
              font-family: var(--vscode-editor-font-family, monospace); font-size: 12px; }
    pre.cov .row { display: flex; white-space: pre; }
    pre.cov .g { flex: 0 0 auto; width: 4.5em; text-align: right; padding-right: 8px; color: var(--vscode-descriptionForeground);
                 user-select: none; opacity: 0.8; border-right: 2px solid transparent; }
    pre.cov .src { flex: 1 1 auto; padding-left: 8px; white-space: pre-wrap; word-break: break-word; }
    pre.cov .hit .g { border-right-color: var(--vscode-testing-iconPassed, #3fb950); }
    pre.cov .hit { background: var(--vscode-diffEditor-insertedLineBackground, rgba(63,185,80,0.12)); }
    pre.cov .miss .g { border-right-color: var(--vscode-testing-iconFailed, #f85149); }
    pre.cov .miss { background: var(--vscode-diffEditor-removedLineBackground, rgba(248,81,73,0.12)); }
    pre.cov .non { opacity: 0.55; }
    pre.cov .hits { color: var(--vscode-testing-iconPassed, #3fb950); }
    /* Profiling table. */
    table.prof { border-collapse: collapse; width: 100%; margin: 4px 0 2px; }
    table.prof th, table.prof td { text-align: right; padding: 2px 8px; border-bottom: 1px solid var(--vscode-panel-border); font-size: 12px; }
    table.prof th:last-child, table.prof td:last-child { text-align: left; width: 40%; }
    .pbar { display: inline-block; height: 9px; border-radius: 2px; background: var(--vscode-progressBar-background, #3794ff); vertical-align: middle; }
    .pbartrack { display: inline-block; width: 100%; background: rgba(127,127,127,0.15); border-radius: 2px; }
    /* Hex pane (#84, ADR 0119): offset gutter · hex bytes · ASCII gutter, monospace. */
    pre.hex { margin: 0; padding: 8px; background: var(--vscode-textCodeBlock-background, rgba(127,127,127,0.1));
              border: 1px solid var(--vscode-panel-border); border-radius: 3px; overflow: auto;
              font-family: var(--vscode-editor-font-family, monospace); font-size: 12px; line-height: 1.5; }
    pre.hex .row { display: flex; white-space: pre; }
    pre.hex .off { flex: 0 0 auto; color: var(--vscode-descriptionForeground); user-select: none; opacity: 0.8; padding-right: 12px; }
    pre.hex .bytes { flex: 1 1 auto; }
    pre.hex .txt { flex: 0 0 auto; padding-left: 12px; color: var(--vscode-descriptionForeground); }
    /* Regression collections (#168, ADR 0121). */
    .phi { color: var(--vscode-list-warningForeground, #d29922); font-size: 12px; margin: 6px 0 10px;
           border-left: 3px solid var(--vscode-list-warningForeground, #d29922); padding-left: 8px; }
    .coll { display: flex; align-items: center; gap: 10px; padding: 6px 0; border-bottom: 1px solid var(--vscode-panel-border); }
    .coll .nm { font-weight: 600; }
    .coll .ct { color: var(--vscode-descriptionForeground); font-size: 12px; flex: 1 1 auto; }
    .badge { padding: 1px 7px; border-radius: 3px; font-size: 12px; font-weight: 600; }
    .badge.pass { color: var(--vscode-testing-iconPassed, #3fb950); }
    .badge.fail { color: var(--vscode-testing-iconFailed, #f85149); }
    .case { padding: 6px 0; border-bottom: 1px solid var(--vscode-panel-border); }
    .case .hd { display: flex; align-items: baseline; gap: 8px; }
    .case .hd .cn { font-size: 13px; }
    .case .hd button { margin-left: auto; padding: 1px 8px; }
    .case .diffs { margin: 4px 0 0 12px; font-size: 12px; color: var(--vscode-descriptionForeground); }
    .case .diffs code { font-family: var(--vscode-editor-font-family, monospace); }
    .case .diffs .del { color: var(--vscode-testing-iconFailed, #f85149); }
    .case .diffs .ins { color: var(--vscode-testing-iconPassed, #3fb950); }
  </style>
</head>
<body>
  <div class="bar">
    <button id="load">Load Message Set</button>
    <button id="savecoll" ${this.rows.length ? "" : "hidden"}>Save as Collection…</button>
    <button id="collections">Collections</button>
    <button id="back" hidden>← Back to results</button>
    <button id="layout" hidden>Side by side</button>
    <button id="tracetoggle" hidden>Show Profiling</button>
  </div>
  <div id="results">${body}</div>
  <div id="detail"></div>
  <script nonce="${n}">${testBenchScript(token)}
  </script>
</body>
</html>`;
  }
}
