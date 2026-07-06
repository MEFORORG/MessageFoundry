// Test Bench: load a message set, dry-run it through the config (no sending), show a results table,
// and a Before/After view per message (side-by-side or above/below) with an HL7 segment/field-aware
// diff — inserted/deleted segments are aligned so they don't cascade false changes, and changed
// fields are highlighted inline (see hl7diff.ts) — plus optional step-through under the debugger.
import * as path from "node:path";
import * as vscode from "vscode";
import { configDir, messageSetsDir, pythonPath, runJson, workspaceDir } from "./cli";
import { diffMessages } from "./hl7diff";

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
    try {
      // One CLI call for all picks (the CLI batches files/folders, splits multi-message files, and
      // returns a `path` per row).
      this.rows = await runJson<DryRunRow[]>(
        // --show-phi: the Test Bench renders the developer's own test messages, so it needs the
        // full bodies the CLI redacts by default.
        ["dryrun", "--config", configDir(), "--show-phi", "--messages", ...picks.map((p) => p.fsPath)],
        cwd,
      );
    } catch (e) {
      void vscode.window.showErrorMessage(`MessageFoundry: dry-run failed — ${String(e)}`);
      return;
    }
    this.render();
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
  </style>
</head>
<body>
  <div class="bar">
    <button id="load">Load Message Set</button>
    <button id="back" hidden>← Back to results</button>
    <button id="layout" hidden>Side by side</button>
  </div>
  <div id="results">${body}</div>
  <div id="detail"></div>
  <script nonce="${n}">
    const vscode = acquireVsCodeApi();
    const results = document.getElementById('results');
    const detail = document.getElementById('detail');
    const back = document.getElementById('back');
    const layout = document.getElementById('layout');
    let sbs = (vscode.getState() || {}).sbs || false; // remembered layout choice

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

    document.getElementById('load').addEventListener('click', () => vscode.postMessage({ command: 'load' }));
    back.addEventListener('click', () => { detail.style.display='none'; results.style.display=''; back.hidden=true; layout.hidden=true; });
    layout.addEventListener('click', () => {
      sbs = !sbs; vscode.setState({ sbs }); layoutLabel();
      const p = document.querySelector('.panes'); if (p) p.classList.toggle('sbs', sbs);
    });
    for (const b of document.querySelectorAll('button[data-act]')) {
      b.addEventListener('click', () => vscode.postMessage({ command: b.dataset.act, index: Number(b.dataset.i) }));
    }

    window.addEventListener('message', (ev) => {
      const m = ev.data;
      if (!m || m.type !== 'detail') return;
      const diff = m.diff || { before: [], after: [] };
      detail.innerHTML =
        '<h3>' + esc(m.source) + ' &rarr; ' + esc(m.to) + '</h3>' +
        '<div class="panes' + (sbs ? ' sbs' : '') + '">' +
          pane('Before (received)', diff.before, 'before') +
          pane('After (would send to ' + m.to + ')', diff.after, 'after') +
        '</div>';
      results.style.display = 'none';
      detail.style.display = 'block';
      back.hidden = false;
      layout.hidden = false;
      layoutLabel();
    });
  </script>
</body>
</html>`;
  }
}
