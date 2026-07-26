// Engine setup — the guided page the status pill leads with in a STORE-LESS workspace (BACKLOG #238,
// ADR 0112 amendment 2026-07-16). A webview, not a QuickPick, because the situation needs room to
// explain: production engines run as a service (docs/SERVICE.md), so an authoring checkout normally
// POINTS at an engine rather than hosting one. The copy and the action buttons live in
// engineSetupContent.ts, deliberately `vscode`-free so the plain-node unit suite can pin them; this
// file is only the panel shell around that model (follows cookbook.ts: CSP, nonce, quote-escaping
// esc(), reveal-if-open, dispose).
//
// Dispatch discipline (mirrors statusBar.ts's QuickPick/hover handlers): the message handler's only
// permitted body is `executeCommand(<known CMD>)`, where the CMD comes from a button looked up in the
// content model by id — NEVER a command string taken from the webview message itself. cookbook.ts is
// the panel-shell template only; its handler inserts snippets and dispatches nothing.
import * as vscode from "vscode";
import { SETUP_LEDE, SETUP_SECTIONS, SETUP_TITLE, buttonById } from "./engineSetupContent";

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

type Incoming = { command: "run"; id: string };

export class EngineSetupPanel {
  private panel: vscode.WebviewPanel | undefined;

  constructor(private readonly context: vscode.ExtensionContext) {}

  open(): void {
    if (this.panel) {
      this.panel.reveal();
      return;
    }
    this.panel = vscode.window.createWebviewPanel(
      "messagefoundry.engineSetup",
      SETUP_TITLE,
      vscode.ViewColumn.Active,
      // No retainContextWhenHidden: the page is static (no search box, no state) — rebuild on reveal.
      { enableScripts: true },
    );
    this.panel.onDidDispose(() => (this.panel = undefined), null, this.context.subscriptions);
    this.panel.webview.onDidReceiveMessage((m: Incoming) => void this.onMessage(m));
    this.panel.webview.html = this.html(this.panel.webview);
  }

  private async onMessage(m: Incoming): Promise<void> {
    if (m.command !== "run") {
      return;
    }
    const btn = buttonById(m.id);
    if (!btn) {
      return;
    }
    // The ONLY permitted body (see the file header): dispatch the CMD the content model declares for
    // this button id. The id selects; the model decides what runs.
    await vscode.commands.executeCommand(btn.command);
  }

  private html(webview: vscode.Webview): string {
    const n = nonce();
    const sections = SETUP_SECTIONS.map((s) => {
      const body = s.body.map((p) => `<p>${esc(p)}</p>`).join("");
      const button = s.button
        ? `<button class="action" data-id="${esc(s.button.id)}">${esc(s.button.label)}</button>`
        : "";
      const badge = s.tone === "dev" ? `<span class="badge">Testing only</span>` : "";
      return (
        `<section class="sec${s.tone === "dev" ? " dev" : ""}">` +
        `<h2>${esc(s.title)}${badge}</h2>${body}${button}</section>`
      );
    }).join("");

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta http-equiv="Content-Security-Policy"
        content="default-src 'none'; style-src ${webview.cspSource} 'unsafe-inline'; script-src 'nonce-${n}';" />
  <style>
    body { font-family: var(--vscode-font-family); color: var(--vscode-foreground);
      padding: 10px 16px 24px; max-width: 720px; }
    h1 { font-size: 15px; margin: 4px 0 2px; }
    p.lede { color: var(--vscode-descriptionForeground); margin: 0 0 14px; font-size: 12px; }
    .sec { border: 1px solid var(--vscode-widget-border, var(--vscode-panel-border)); border-radius: 6px;
      padding: 10px 12px 12px; background: var(--vscode-editorWidget-background); margin: 0 0 12px; }
    h2 { font-size: 13px; margin: 2px 0 4px; }
    .sec p { font-size: 12px; color: var(--vscode-descriptionForeground); margin: 4px 0 8px; }
    button.action { font-family: inherit; font-size: 12px; padding: 4px 10px; cursor: pointer;
      color: var(--vscode-button-foreground); background: var(--vscode-button-background);
      border: none; border-radius: 3px; }
    button.action:hover { background: var(--vscode-button-hoverBackground); }
    /* The test-only developer-engine block: visually separated from the production guidance above
       (ADR 0112 amendment §2 — "clearly labelled, context-honest"). */
    .sec.dev { margin-top: 22px; border-color: var(--vscode-editorWarning-foreground, #cca700); }
    .badge { font-size: 10px; text-transform: uppercase; letter-spacing: .04em; margin-left: 8px;
      color: var(--vscode-editorWarning-foreground, #cca700); border: 1px solid currentColor;
      border-radius: 8px; padding: 0 6px; white-space: nowrap; vertical-align: middle; }
  </style>
</head>
<body>
  <h1>${esc(SETUP_TITLE)}</h1>
  <p class="lede">${esc(SETUP_LEDE)}</p>
  ${sections}
  <script nonce="${n}">
    const vscode = acquireVsCodeApi();
    for (const btn of document.querySelectorAll('button.action')) {
      btn.addEventListener('click', () => vscode.postMessage({ command: 'run', id: btn.dataset.id }));
    }
  </script>
</body>
</html>`;
  }
}
