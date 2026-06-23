// "Home" — a webview view at the top of the MessageFoundry sidebar: grouped action cards that run
// extension commands. Every action is live; the `soon` flag renders a "soon" badge for any action
// still queued in the backlog. Monitoring + engine run/stop deliberately live in the Console, not here.
import * as vscode from "vscode";

interface Action {
  id: string; // command id
  label: string;
  soon?: boolean;
}

const GROUPS: { title: string; actions: Action[] }[] = [
  {
    title: "Authoring",
    actions: [
      { id: "messagefoundry.newRoute", label: "New Route Wizard" },
      { id: "messagefoundry.newConnection", label: "New Connection" },
      { id: "messagefoundry.newRouter", label: "New Router" },
      { id: "messagefoundry.newHandler", label: "New Handler" },
      { id: "messagefoundry.newAlert", label: "New Alert" },
    ],
  },
  {
    title: "Test & data",
    actions: [
      { id: "messagefoundry.openTestBench", label: "Open Test Bench" },
      { id: "messagefoundry.validate", label: "Validate Config" },
      { id: "messagefoundry.generateSamples", label: "Generate Samples" },
    ],
  },
  {
    title: "Operate",
    actions: [
      { id: "messagefoundry.setupSourceControl", label: "Set Up Version Control & Checks" },
      { id: "messagefoundry.promote", label: "Stage → Promote" },
    ],
  },
];

function nonce(): string {
  let s = "";
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  for (let i = 0; i < 24; i++) {
    s += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return s;
}

function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

export class HomeView implements vscode.WebviewViewProvider {
  resolveWebviewView(view: vscode.WebviewView): void {
    view.webview.options = { enableScripts: true };
    view.webview.onDidReceiveMessage((m: { command?: string; id?: string }) => {
      if (m?.command === "run" && typeof m.id === "string") {
        void vscode.commands.executeCommand(m.id);
      }
    });
    view.webview.html = this.html(view.webview);
  }

  private html(webview: vscode.Webview): string {
    const n = nonce();
    const groups = GROUPS.map(
      (g) =>
        `<div class="group"><div class="title">${esc(g.title)}</div>${g.actions
          .map(
            (a) =>
              `<button class="action" data-cmd="${esc(a.id)}">${esc(a.label)}${
                a.soon ? '<span class="soon">soon</span>' : ""
              }</button>`,
          )
          .join("")}</div>`,
    ).join("");

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta http-equiv="Content-Security-Policy"
        content="default-src 'none'; style-src ${webview.cspSource} 'unsafe-inline'; script-src 'nonce-${n}';" />
  <style>
    body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); padding: 6px 8px; }
    .group { margin-bottom: 12px; }
    .title { font-size: 11px; text-transform: uppercase; letter-spacing: .04em;
      color: var(--vscode-descriptionForeground); margin: 6px 2px; }
    button.action { display: flex; align-items: center; justify-content: space-between; width: 100%;
      text-align: left; font-family: inherit; font-size: 13px; margin: 3px 0; padding: 6px 10px; cursor: pointer;
      color: var(--vscode-button-secondaryForeground); background: var(--vscode-button-secondaryBackground);
      border: none; border-radius: 3px; }
    button.action:hover { background: var(--vscode-button-hoverBackground); }
    .soon { font-size: 10px; text-transform: uppercase; opacity: .7;
      border: 1px solid currentColor; border-radius: 8px; padding: 0 6px; margin-left: 8px; }
  </style>
</head>
<body>
  ${groups}
  <script nonce="${n}">
    const vscode = acquireVsCodeApi();
    for (const b of document.querySelectorAll('button.action')) {
      b.addEventListener('click', () => vscode.postMessage({ command: 'run', id: b.dataset.cmd }));
    }
  </script>
</body>
</html>`;
  }
}
