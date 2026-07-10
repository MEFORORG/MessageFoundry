// Cookbook — a searchable "solved problems" gallery webview (BACKLOG #104). Mirrors Corepoint's
// cookbook of pre-built integration patterns: browse/search a recipe by name, then INSERT its real,
// editable Python via `editor.insertSnippet` — the same insertion primitive as Insert Element
// (insertElement.ts) and the scaffold snippets. This is the deterministic, OFFLINE sibling to the AI
// chat's `/explain` (chat.ts): no model call, no network, works with the extension's Python CLI
// entirely absent.
//
// The recipe catalog itself (data + search matching) lives in cookbookRecipes.ts, deliberately
// `vscode`-free so it's unit-testable under plain Node/Mocha; this file is just the webview shell
// around it (follows home.ts's pattern: CSP, nonce, message passing, styling).
import * as vscode from "vscode";
import { RECIPES, searchBlob } from "./cookbookRecipes";

function nonce(): string {
  let s = "";
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  for (let i = 0; i < 24; i++) {
    s += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return s;
}

function esc(s: string): string {
  // Escape quotes too, not just &<>: these values land inside double-quoted HTML attributes
  // (e.g. data-id="${esc(...)}"), so an unescaped " would break out of the attribute.
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

type Incoming = { command: "insert"; id: string };

export class CookbookPanel {
  private panel: vscode.WebviewPanel | undefined;

  constructor(private readonly context: vscode.ExtensionContext) {}

  open(): void {
    if (this.panel) {
      this.panel.reveal();
      return;
    }
    this.panel = vscode.window.createWebviewPanel(
      "messagefoundry.cookbook",
      "MessageFoundry Cookbook",
      vscode.ViewColumn.Beside,
      { enableScripts: true, retainContextWhenHidden: true },
    );
    this.panel.onDidDispose(() => (this.panel = undefined), null, this.context.subscriptions);
    this.panel.webview.onDidReceiveMessage((m: Incoming) => void this.onMessage(m));
    this.panel.webview.html = this.html(this.panel.webview);
  }

  private async onMessage(m: Incoming): Promise<void> {
    if (m.command !== "insert") {
      return;
    }
    const recipe = RECIPES.find((r) => r.id === m.id);
    if (!recipe) {
      return;
    }
    const editor = vscode.window.activeTextEditor;
    if (!editor || editor.document.languageId !== "python") {
      void vscode.window.showInformationMessage(
        "MessageFoundry: open a Python config file to insert a recipe.",
      );
      return;
    }
    await editor.insertSnippet(new vscode.SnippetString(recipe.code));
  }

  private html(webview: vscode.Webview): string {
    const n = nonce();
    const cards = RECIPES.map(
      (r) =>
        `<div class="card" data-id="${esc(r.id)}" data-search="${esc(searchBlob(r))}">` +
        `<div class="cardHead"><span class="cat">${esc(r.category)}</span>` +
        `<h3>${esc(r.title)}</h3></div>` +
        `<p class="summary">${esc(r.summary)}</p>` +
        `<pre><code>${esc(r.code)}</code></pre>` +
        `<button class="insert" data-id="${esc(r.id)}">Insert into editor</button>` +
        `</div>`,
    ).join("");

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta http-equiv="Content-Security-Policy"
        content="default-src 'none'; style-src ${webview.cspSource} 'unsafe-inline'; script-src 'nonce-${n}';" />
  <style>
    body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); padding: 10px 16px 24px; }
    h1 { font-size: 15px; margin: 4px 0 2px; }
    p.lede { color: var(--vscode-descriptionForeground); margin: 0 0 12px; font-size: 12px; }
    input#search { width: 100%; box-sizing: border-box; padding: 6px 8px; font-size: 13px;
      margin-bottom: 14px; background: var(--vscode-input-background); color: var(--vscode-input-foreground);
      border: 1px solid var(--vscode-input-border, transparent); border-radius: 3px; }
    #count { color: var(--vscode-descriptionForeground); font-size: 11px; margin: -8px 0 12px; }
    .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 12px; }
    .card { border: 1px solid var(--vscode-widget-border, var(--vscode-panel-border)); border-radius: 6px;
      padding: 10px 12px; background: var(--vscode-editorWidget-background); display: flex; flex-direction: column; }
    .card.hidden { display: none; }
    .cardHead { display: flex; align-items: baseline; gap: 8px; flex-wrap: wrap; }
    .cat { font-size: 10px; text-transform: uppercase; letter-spacing: .04em;
      color: var(--vscode-descriptionForeground); border: 1px solid currentColor; border-radius: 8px;
      padding: 0 6px; white-space: nowrap; }
    h3 { font-size: 13px; margin: 2px 0; }
    p.summary { font-size: 12px; color: var(--vscode-descriptionForeground); margin: 4px 0 8px; }
    pre { background: var(--vscode-textCodeBlock-background); border-radius: 4px; padding: 8px;
      overflow-x: auto; margin: 0 0 10px; flex: 1; }
    code { font-family: var(--vscode-editor-font-family, monospace); font-size: 12px; white-space: pre; }
    button.insert { align-self: flex-start; font-family: inherit; font-size: 12px; padding: 4px 10px;
      cursor: pointer; color: var(--vscode-button-foreground); background: var(--vscode-button-background);
      border: none; border-radius: 3px; }
    button.insert:hover { background: var(--vscode-button-hoverBackground); }
    #empty { display: none; color: var(--vscode-descriptionForeground); font-size: 12px; margin-top: 8px; }
  </style>
</head>
<body>
  <h1>Cookbook</h1>
  <p class="lede">Solved HL7 routing/transform problems, as real Python. Search, then insert into the active editor and edit it there.</p>
  <input id="search" type="text" placeholder="Search recipes (e.g. “code set”, “split”, “fan-out”)…" />
  <div id="count"></div>
  <div class="grid" id="grid">
    ${cards}
  </div>
  <div id="empty">No recipes match.</div>
  <script nonce="${n}">
    const vscode = acquireVsCodeApi();
    const cards = Array.from(document.querySelectorAll('.card'));
    const countEl = document.getElementById('count');
    const emptyEl = document.getElementById('empty');

    function applyFilter(query) {
      const q = query.trim().toLowerCase();
      let shown = 0;
      for (const card of cards) {
        const match = q === '' || card.dataset.search.includes(q);
        card.classList.toggle('hidden', !match);
        if (match) { shown++; }
      }
      countEl.textContent = shown + ' of ' + cards.length + ' recipes';
      emptyEl.style.display = shown === 0 ? 'block' : 'none';
    }
    applyFilter('');

    const search = document.getElementById('search');
    search.addEventListener('input', () => applyFilter(search.value));

    for (const btn of document.querySelectorAll('button.insert')) {
      btn.addEventListener('click', () => vscode.postMessage({ command: 'insert', id: btn.dataset.id }));
    }
  </script>
</body>
</html>`;
  }
}
