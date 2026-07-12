// "Home" — a webview view at the top of the MessageFoundry sidebar: grouped action cards that run
// extension commands. Every action is live; the `soon` flag renders a "soon" badge for any action
// still queued in the backlog. Monitoring + engine run/stop deliberately live in the Console, not here.
import * as vscode from "vscode";

interface Action {
  id: string; // command id
  label: string;
  soon?: boolean;
}

const GROUPS: { title: string; actions: Action[]; collapsed?: boolean }[] = [
  {
    title: "Wizards",
    actions: [
      { id: "messagefoundry.newRoute", label: "Route Wizard" },
      { id: "messagefoundry.newConnection", label: "Connection Wizard" },
      { id: "messagefoundry.newRouter", label: "Router Wizard" },
      { id: "messagefoundry.newHandler", label: "Handler Wizard" },
      { id: "messagefoundry.newAlert", label: "Alert Wizard" },
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
    actions: [{ id: "messagefoundry.promote", label: "Stage → Promote" }],
  },
  {
    // One-time setup + config, tucked below the everyday actions and collapsed by default so it
    // stays out of the way. Also the discoverable home for the extension's settings (liveStatus, …).
    title: "Setup",
    collapsed: true,
    actions: [
      { id: "messagefoundry.setupSourceControl", label: "Set Up Version Control & Checks" },
      { id: "messagefoundry.setRepoStorage", label: "Config Repo Storage Location" },
      { id: "messagefoundry.openSettings", label: "Extension Settings" },
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
  // Escape quotes too, not just &<>: these values land inside double-quoted HTML attributes
  // (e.g. data-cmd="${esc(...)}"), so an unescaped " would break out of the attribute.
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export class HomeView implements vscode.WebviewViewProvider {
  private view: vscode.WebviewView | undefined;

  // `onFilter` drives the Connections tree filter live from the persistent search box (the always-
  // visible sibling of the funnel command — a TreeView can't host an input, so it lives here at the top
  // of the sidebar). `currentFilter` seeds the box with any filter already active.
  constructor(
    private readonly onFilter: (text: string) => void = () => {},
    private readonly currentFilter: () => string = () => "",
  ) {}

  resolveWebviewView(view: vscode.WebviewView): void {
    this.view = view;
    view.webview.options = { enableScripts: true };
    view.webview.onDidReceiveMessage((m: { command?: string; id?: string; text?: string }) => {
      if (m?.command === "run" && typeof m.id === "string") {
        void vscode.commands.executeCommand(m.id);
      } else if (m?.command === "filter") {
        this.onFilter(typeof m.text === "string" ? m.text : "");
      }
    });
    view.webview.html = this.html(view.webview, this.currentFilter());
  }

  /** Reflect an externally-set filter (e.g. the funnel command) back into the search box. */
  setFilterText(text: string): void {
    void this.view?.webview.postMessage({ command: "setFilter", text });
  }

  private html(webview: vscode.Webview, initialFilter: string): string {
    const n = nonce();
    const groups = GROUPS.map(
      (g) =>
        `<details class="group" data-key="${esc(g.title)}" data-default="${
          g.collapsed ? "closed" : "open"
        }"${g.collapsed ? "" : " open"}><summary class="title">${esc(
          g.title,
        )}</summary><div class="body">${g.actions
          .map(
            (a) =>
              `<button class="action" data-cmd="${esc(a.id)}">${esc(a.label)}${
                a.soon ? '<span class="soon">soon</span>' : ""
              }</button>`,
          )
          .join("")}</div></details>`,
    ).join("");

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta http-equiv="Content-Security-Policy"
        content="default-src 'none'; style-src ${webview.cspSource} 'unsafe-inline'; script-src 'nonce-${n}';" />
  <style>
    body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); padding: 4px 8px; }
    .search { margin: 3px 2px 9px; }
    .search input { width: 100%; box-sizing: border-box; font-family: inherit; font-size: 13px;
      color: var(--vscode-input-foreground); background: var(--vscode-input-background);
      border: 1px solid var(--vscode-input-border, var(--vscode-panel-border)); border-radius: 3px;
      padding: 4px 8px; }
    .search input::placeholder { color: var(--vscode-input-placeholderForeground); }
    .group { margin-bottom: 6px; }
    summary.title { display: flex; align-items: center; gap: 4px; font-size: 11px; text-transform: uppercase;
      letter-spacing: .04em; color: var(--vscode-descriptionForeground); margin: 3px 2px; cursor: pointer;
      user-select: none; list-style: none; }
    summary.title::-webkit-details-marker { display: none; }
    summary.title::before { content: "▸"; font-size: 14px; transition: transform .12s ease; }
    details[open] > summary.title::before { transform: rotate(90deg); }
    details:not([open]) > .body { display: none; }
    button.action { display: flex; align-items: center; justify-content: space-between; width: 100%;
      text-align: left; font-family: inherit; font-size: 13px; margin: 1px 0; padding: 5px 10px; cursor: pointer;
      color: var(--vscode-button-secondaryForeground); background: var(--vscode-button-secondaryBackground);
      border: none; border-radius: 3px; }
    button.action:hover { background: var(--vscode-button-hoverBackground); }
    .soon { font-size: 10px; text-transform: uppercase; opacity: .7;
      border: 1px solid currentColor; border-radius: 8px; padding: 0 6px; margin-left: 8px; }
  </style>
</head>
<body>
  <div class="search">
    <input id="search" type="search" spellcheck="false"
           placeholder="Find connection, handler, router, transform…" value="${esc(initialFilter)}" />
  </div>
  ${groups}
  <script nonce="${n}">
    const vscode = acquireVsCodeApi();
    // Persistent filter box for the Connections tree (drives graph.setFilter → also the #228
    // Definitions). Debounced so each keystroke doesn't re-project the tree; two-way synced with the
    // funnel command via an inbound 'setFilter' message.
    const search = document.getElementById('search');
    let filterTimer;
    search.addEventListener('input', () => {
      clearTimeout(filterTimer);
      filterTimer = setTimeout(() => vscode.postMessage({ command: 'filter', text: search.value }), 150);
    });
    search.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && search.value) {
        search.value = '';
        vscode.postMessage({ command: 'filter', text: '' });
      }
    });
    window.addEventListener('message', (e) => {
      if (e.data && e.data.command === 'setFilter' && e.data.text !== search.value) {
        search.value = e.data.text;
      }
    });
    const state = vscode.getState() || {};
    const collapsed = state.collapsed || (state.collapsed = {});
    for (const d of document.querySelectorAll('details.group')) {
      const key = d.dataset.key;
      // Persisted choice wins; otherwise fall back to the group's declared default (Setup ships closed).
      d.open = (key in collapsed) ? !collapsed[key] : (d.dataset.default === 'open');
      d.addEventListener('toggle', () => {
        collapsed[key] = !d.open;
        vscode.setState(state);
      });
    }
    for (const b of document.querySelectorAll('button.action')) {
      b.addEventListener('click', () => vscode.postMessage({ command: 'run', id: b.dataset.cmd }));
    }
  </script>
</body>
</html>`;
  }
}
