// Test Bench: load a message set, dry-run it through the config (no sending), show a results table,
// and a Before/After view per message (side-by-side or above/below) with an HL7 segment/field-aware
// diff — inserted/deleted segments are aligned so they don't cascade false changes, and changed
// fields are highlighted inline (see hl7diff.ts) — plus a Coverage/Profiling view per message (which
// Router/Handler lines ran + per-line time, from `dryrun --trace json`, see traceView.ts) and optional
// step-through under the debugger.
import * as fs from "node:fs";
import * as path from "node:path";
import * as vscode from "vscode";
import { configDir, messageSetsDir, pythonPath, runJson, workspaceDir } from "./cli";
import { diffMessages } from "./hl7diff";
import { buildTraceDetail, type TraceDetail, type TraceEntry } from "./traceView";

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
  | { command: "debug"; index: number };

function nonce(): string {
  let s = "";
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  for (let i = 0; i < 24; i++) {
    s += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return s;
}

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
    this.panel.onDidDispose(() => (this.panel = undefined), null, this.context.subscriptions);
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
    }
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
    await this.panel.webview.postMessage({ type: "trace", detail });
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
    await this.panel.webview.postMessage({
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
            <button data-act="trace" data-i="${i}">Coverage / Profile</button>
            <button data-act="debug" data-i="${i}">Debug</button>
          </td>
        </tr>`;
      })
      .join("");
  }

  private html(webview: vscode.Webview): string {
    const n = nonce();
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
  </style>
</head>
<body>
  <div class="bar">
    <button id="load">Load Message Set</button>
    <button id="back" hidden>← Back to results</button>
    <button id="layout" hidden>Side by side</button>
    <button id="tracetoggle" hidden>Show Profiling</button>
  </div>
  <div id="results">${body}</div>
  <div id="detail"></div>
  <script nonce="${n}">
    const vscode = acquireVsCodeApi();
    const results = document.getElementById('results');
    const detail = document.getElementById('detail');
    const back = document.getElementById('back');
    const layout = document.getElementById('layout');
    const tracetoggle = document.getElementById('tracetoggle');
    let sbs = (vscode.getState() || {}).sbs || false; // remembered layout choice
    let traceMode = (vscode.getState() || {}).traceMode || 'coverage'; // 'coverage' | 'profile'
    let lastTrace = null; // the most recent trace detail, so the toggle can re-render it

    function esc(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

    // Render one side of the HL7-aware diff. The cells are aligned so before[i] lines up with
    // after[i]: a gap cell (seg=false) holds the place opposite an inserted/deleted segment, and
    // each segment's changed fields are highlighted inline (side picks red 'del' vs green 'ins').
    function pane(label, cells, side){
      const span = side === 'before' ? 'del' : 'ins';
      const html = cells.map((cell) => {
        if (!cell.seg) return '<div class="ln gap">&nbsp;</div>';
        let cls = 'ln';
        if (cell.status === 'added') cls += ' ln-ins';
        else if (cell.status === 'removed') cls += ' ln-del';
        const inner = cell.fields.map((f) =>
          f.c ? '<span class="' + span + '">' + (esc(f.t) || '&nbsp;') + '</span>' : esc(f.t)
        ).join(esc(cell.sep));
        return '<div class="' + cls + '">' + (inner || '&nbsp;') + '</div>';
      }).join('');
      return '<div class="pane"><div class="lbl">' + esc(label) + '</div><pre>' + html + '</pre></div>';
    }

    function layoutLabel(){ layout.textContent = sbs ? 'Top / bottom' : 'Side by side'; }
    function traceToggleLabel(){ tracetoggle.textContent = traceMode === 'coverage' ? 'Show Profiling' : 'Show Coverage'; }

    // Human-readable time from seconds (traced wall time; includes tracer overhead, so comparative).
    function fmtTime(s){
      if (!(s > 0)) return '0';
      if (s < 1e-6) return (s * 1e9).toFixed(0) + ' ns';
      if (s < 1e-3) return (s * 1e6).toFixed(1) + ' µs';
      if (s < 1) return (s * 1e3).toFixed(2) + ' ms';
      return s.toFixed(3) + ' s';
    }
    function pct(p){ return (p || 0).toFixed(p >= 10 ? 0 : 1) + '%'; }

    // COVERAGE: source lines of one @router/@handler, executed (green) vs not (red) vs context (dim).
    function coverageInv(cov){
      const head = '<h4><span class="kind">' + esc(cov.kind) + '</span> ' + esc(cov.name) +
        ' <span class="meta">' + cov.executed + '/' + cov.executable + ' lines' +
        (cov.executable ? ' &middot; ' + pct(cov.pct) : '') + '</span></h4>';
      const notes =
        (cov.truncated ? '<div class="note">Trace hit its event cap — coverage may under-report.</div>' : '') +
        (cov.sourceAvailable ? '' : '<div class="note">Source file unavailable — showing executed lines only.</div>');
      const rows = cov.lines.map((l) => {
        let cls = 'row non';
        if (l.executable) cls = l.executed ? 'row hit' : 'row miss';
        const hits = l.hits > 1 ? ' <span class="hits">&times;' + l.hits + '</span>' : '';
        const src = cov.sourceAvailable ? (esc(l.text) || '&nbsp;') : ('line ' + l.line + ' executed');
        return '<div class="' + cls + '"><span class="g">' + l.line + hits + '</span><span class="src">' + src + '</span></div>';
      }).join('');
      return '<div class="inv">' + head + notes + '<pre class="cov">' + rows + '</pre></div>';
    }

    // PROFILING: per-invocation total + a per-line time/%/bar table (hottest first).
    function profileInv(prof){
      const head = '<h4><span class="kind">' + esc(prof.kind) + '</span> ' + esc(prof.name) +
        ' <span class="meta">' + fmtTime(prof.totalSeconds) + ' total</span></h4>';
      if (!prof.hasTiming) {
        return '<div class="inv">' + head + '<div class="note">This trace carried no timing.</div></div>';
      }
      if (!prof.lines.length) {
        return '<div class="inv">' + head + '<div class="note">No lines executed.</div></div>';
      }
      const body = prof.lines.map((l) => {
        const bar = '<span class="pbartrack"><span class="pbar" style="width:' + Math.max(0, Math.min(100, l.pct)).toFixed(1) + '%"></span></span>';
        return '<tr><td>' + l.line + '</td><td>' + l.hits + '</td><td>' + fmtTime(l.seconds) +
          '</td><td>' + pct(l.pct) + '</td><td>' + bar + '</td></tr>';
      }).join('');
      return '<div class="inv">' + head +
        '<table class="prof"><thead><tr><th>Line</th><th>Hits</th><th>Time</th><th>%</th><th>Share</th></tr></thead>' +
        '<tbody>' + body + '</tbody></table></div>';
    }

    function renderTrace(){
      if (!lastTrace) return;
      const t = lastTrace;
      let inner;
      if (traceMode === 'profile') {
        const summary = t.hasTiming
          ? '<div class="note">Total traced time ' + fmtTime(t.totalSeconds) + ' &middot; timings include tracer overhead (comparative, not a benchmark).</div>'
          : '<div class="note">This trace carried no per-line timing.</div>';
        inner = summary + t.invocations.map((v) => profileInv(v.profile)).join('');
      } else {
        inner = '<div class="note">Green = executed &middot; red = not executed &middot; dim = non-executable (def / comment / blank).</div>' +
          t.invocations.map((v) => coverageInv(v.coverage)).join('');
      }
      const label = traceMode === 'profile' ? 'Profiling' : 'Coverage';
      detail.innerHTML = '<h3>' + label + ' — ' + esc(t.source) +
        ' <span class="meta">(' + esc(t.disposition) + ')</span></h3>' +
        (t.invocations.length ? inner : '<div class="note">No Router/Handler ran for this message.</div>');
    }

    function saveState(){ vscode.setState({ sbs, traceMode }); }

    document.getElementById('load').addEventListener('click', () => vscode.postMessage({ command: 'load' }));
    back.addEventListener('click', () => {
      detail.style.display='none'; results.style.display=''; lastTrace=null;
      back.hidden=true; layout.hidden=true; tracetoggle.hidden=true;
    });
    layout.addEventListener('click', () => {
      sbs = !sbs; saveState(); layoutLabel();
      const p = document.querySelector('.panes'); if (p) p.classList.toggle('sbs', sbs);
    });
    tracetoggle.addEventListener('click', () => {
      traceMode = traceMode === 'coverage' ? 'profile' : 'coverage'; saveState();
      traceToggleLabel(); renderTrace();
    });
    for (const b of document.querySelectorAll('button[data-act]')) {
      b.addEventListener('click', () => vscode.postMessage({ command: b.dataset.act, index: Number(b.dataset.i) }));
    }

    window.addEventListener('message', (ev) => {
      const m = ev.data;
      if (!m) return;
      if (m.type === 'detail') {
        const diff = m.diff || { before: [], after: [] };
        detail.innerHTML =
          '<h3>' + esc(m.source) + ' &rarr; ' + esc(m.to) + '</h3>' +
          '<div class="panes' + (sbs ? ' sbs' : '') + '">' +
            pane('Before (received)', diff.before, 'before') +
            pane('After (would send to ' + m.to + ')', diff.after, 'after') +
          '</div>';
        lastTrace = null;
        results.style.display = 'none';
        detail.style.display = 'block';
        back.hidden = false;
        layout.hidden = false;
        tracetoggle.hidden = true;
        layoutLabel();
      } else if (m.type === 'trace') {
        lastTrace = m.detail;
        renderTrace();
        results.style.display = 'none';
        detail.style.display = 'block';
        back.hidden = false;
        layout.hidden = true;
        tracetoggle.hidden = false;
        traceToggleLabel();
      }
    });
  </script>
</body>
</html>`;
  }
}
