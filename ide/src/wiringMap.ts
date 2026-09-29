// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Wiring Map (ADR 0091 D3): a READ-ONLY, focus-first graph panel over the one wiring graph — an
// on-demand editor-area webview (the Nx Console pattern), never a sidebar surface and never the
// whole estate by default. Strictly a projection of wiringMapModel's output: four labelled columns
// (inbound | router | handler | outbound), kind-accented nodes, provenance-styled edges (solid =
// declared/literal, dashed = heuristic, dashed-to-"?" for dynamic stubs). No drag-drop, no editing
// of any kind (BACKLOG #26 declined-by-design — the .py stays the only artifact); the only
// interactions are select/highlight, open-source, and reveal-in-tree. Webview discipline follows
// testBench.ts/cookbook.ts: HTML string + nonce CSP, zero external resources, no frameworks,
// theme via var(--vscode-*). The SVG itself is built webview-side with createElementNS from the
// posted map payload, so config-supplied names are never string-interpolated into markup.
import * as vscode from "vscode";
import type { ElementKind } from "./graphModel";
import { wiringMapPayload, type MapFocus } from "./wiringMapModel";
import type { GraphProvider } from "./graphTree";
import { openChannel, postToWebview } from "./webviewMessaging";
import { wiringMapScript } from "./wiringMapWebview";

type Incoming =
  | { command: "ready" }
  | { command: "setFocus"; kind: ElementKind; name: string }
  | { command: "refresh" }
  | { command: "open"; file: string; line: number }
  | { command: "reveal"; kind: ElementKind; name: string };

export class WiringMapPanel {
  private panel: vscode.WebviewPanel | undefined;
  private treeSub: vscode.Disposable | undefined;
  private focus: MapFocus | null = null;

  constructor(
    private readonly context: vscode.ExtensionContext,
    private readonly graph: GraphProvider,
  ) {}

  /** Open (or reveal) the singleton panel, optionally re-focusing it on an element. */
  open(focus?: MapFocus): void {
    if (focus) {
      this.focus = focus;
    }
    if (this.panel) {
      this.panel.reveal();
      this.post();
      return;
    }
    this.panel = vscode.window.createWebviewPanel(
      "messagefoundry.wiringMap",
      "Wiring Map",
      vscode.ViewColumn.Active,
      { enableScripts: true, retainContextWhenHidden: true },
    );
    // Stay live: whenever the CONNECTIONS provider re-reads the graph (save, manual refresh), pull
    // the new graph and re-render. The subscription dies with the panel — dispose cleanly.
    this.treeSub = this.graph.onDidChangeTreeData(() => this.post());
    this.panel.onDidDispose(
      () => {
        this.treeSub?.dispose();
        this.treeSub = undefined;
        this.panel = undefined;
      },
      null,
      this.context.subscriptions,
    );
    this.panel.webview.onDidReceiveMessage((m: Incoming) => void this.onMessage(m));
    this.panel.webview.html = this.html(this.panel.webview);
    // The webview posts "ready" once its script runs; the first map payload answers it.
  }

  private async onMessage(m: Incoming): Promise<void> {
    if (m.command === "ready") {
      this.post();
    } else if (m.command === "setFocus") {
      this.focus = { kind: m.kind, name: m.name };
      this.post();
    } else if (m.command === "refresh") {
      await this.graph.refresh(); // fires onDidChangeTreeData -> post()
    } else if (m.command === "open") {
      await vscode.commands.executeCommand("messagefoundry.openSource", m.file, m.line);
    } else if (m.command === "reveal") {
      await vscode.commands.executeCommand("messagefoundry.revealElement", m.kind, m.name);
    }
  }

  /** Build the focused map from the provider's current graph and push it to the webview. */
  private post(): void {
    if (!this.panel) {
      return;
    }
    // Built by a pure function so the webview's shape check is tested against exactly this message.
    const payload = wiringMapPayload(this.graph.getGraph(), this.focus);
    void postToWebview(this.panel.webview, { ...payload });
  }

  private html(webview: vscode.Webview): string {
    const { nonce: n, token } = openChannel(webview);
    // All dynamic content (element names from the user's config) reaches this document ONLY via
    // postMessage + createElementNS/textContent — nothing config-derived is interpolated here.
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta http-equiv="Content-Security-Policy"
        content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${n}';" />
  <style>
    body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); padding: 0 12px; }
    .bar { padding: 10px 0; position: sticky; top: 0; z-index: 2; background: var(--vscode-editor-background);
           display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
    .bar .focuslbl { font-weight: 600; max-width: 34ch; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .bar .focuslbl .kind { color: var(--vscode-descriptionForeground); font-weight: 600;
                           text-transform: uppercase; font-size: 11px; margin-right: 4px; }
    button { font-family: inherit; color: var(--vscode-button-foreground); background: var(--vscode-button-background);
             border: none; padding: 4px 10px; cursor: pointer; border-radius: 2px; }
    button:hover { background: var(--vscode-button-hoverBackground); }
    button:disabled { opacity: 0.5; cursor: default; }
    select, input { font-family: inherit; color: var(--vscode-input-foreground); background: var(--vscode-input-background);
                    border: 1px solid var(--vscode-input-border, transparent); padding: 3px 6px; border-radius: 2px; }
    input { min-width: 220px; }
    label { color: var(--vscode-descriptionForeground); font-size: 12px; }
    .note { color: var(--vscode-descriptionForeground); font-size: 12px; margin: 2px 0 6px; }
    .warn { color: var(--vscode-list-warningForeground, #d29922); }
    .stage { display: flex; align-items: flex-start; gap: 28px; }
    #canvas { overflow: auto; flex: 0 1 auto; min-width: 0; }
    svg { display: block; }
    svg text { font-family: var(--vscode-font-family); fill: var(--vscode-foreground); }
    .colhead { font-size: 11px; font-weight: 700; fill: var(--vscode-descriptionForeground); letter-spacing: 0.06em; }
    .node rect.box { fill: var(--vscode-editorWidget-background, var(--vscode-editor-background));
                     stroke: var(--vscode-panel-border, #666); rx: 4; }
    .node { cursor: pointer; }
    .node text.name { font-size: 12px; }
    .node text.sub { font-size: 10px; fill: var(--vscode-descriptionForeground); }
    /* Kind accents — match the tree/Steps rows: blue = router, green = handler; connections keep a
       neutral accent and are identified by their arrow glyph. */
    .node.k-router rect.accent { fill: var(--vscode-charts-blue, #3794ff); }
    .node.k-handler rect.accent { fill: var(--vscode-charts-green, #89d185); }
    .node.k-inbound rect.accent, .node.k-outbound rect.accent { fill: var(--vscode-descriptionForeground, #999); }
    .node.focus rect.box { stroke: var(--vscode-focusBorder, #007fd4); stroke-width: 2; }
    .node.selected rect.box { stroke: var(--vscode-focusBorder, #007fd4); stroke-width: 2;
                              fill: var(--vscode-list-activeSelectionBackground, rgba(0,127,212,0.2)); }
    .node.stub rect.box { stroke-dasharray: 3 3; fill: none; }
    .node.stub text.name { fill: var(--vscode-descriptionForeground); }
    .edge { fill: none; stroke: var(--vscode-charts-lines, var(--vscode-descriptionForeground, #888));
            stroke-width: 1.4; opacity: 0.85; }
    .edge.p-heuristic, .edge.p-dynamic { stroke-dasharray: 5 4; }
    .edge.dim { opacity: 0.15; }
    .edge.hi { stroke: var(--vscode-focusBorder, #007fd4); stroke-width: 2; opacity: 1; }
    .node.dim { opacity: 0.35; }
    .legend { display: flex; flex-direction: column; gap: 6px; align-items: flex-start; padding: 2px 0; flex: 0 0 auto;
              color: var(--vscode-descriptionForeground); font-size: 11px; }
    .legend .sw { display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: 4px; vertical-align: -1px; }
    .legend .ln { display: inline-block; width: 26px; border-top: 2px solid var(--vscode-descriptionForeground);
                  margin-right: 4px; vertical-align: 3px; }
    .legend .ln.dash { border-top-style: dashed; }
    /* Hover tooltips anchored ABOVE the control (the native title attribute shows below the cursor).
       Toolbar controls sit flush at the top, so their tooltips flip below to stay on-screen (.bar). */
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
    .bar [data-tip]:hover::after { top: calc(100% + 8px); bottom: auto; }
    .bar [data-tip]:hover::before { top: calc(100% + 3px); bottom: auto;
      border-top-color: transparent;
      border-bottom-color: var(--vscode-editorHoverWidget-border, var(--vscode-panel-border)); }
  </style>
</head>
<body>
  <div class="bar">
    <span class="focuslbl" id="focusLbl" data-tip="Current focus element"></span>
    <input id="search" list="elementNames" placeholder="Jump to an element…" />
    <datalist id="elementNames"></datalist>
    <button id="refresh" data-tip="Re-read the wiring graph">Refresh</button>
    <button id="reveal" disabled data-tip="Reveal the selected node in the Connections tree">Reveal in tree</button>
  </div>
  <div id="note" class="note"></div>
  <div class="stage">
  <div id="canvas"></div>
  <div class="legend">
    <span><span class="sw" style="background: var(--vscode-charts-blue, #3794ff)"></span>router</span>
    <span><span class="sw" style="background: var(--vscode-charts-green, #89d185)"></span>handler</span>
    <span>→ inbound / outbound connection</span>
    <span><span class="ln"></span>declared / literal</span>
    <span><span class="ln dash"></span>heuristic</span>
    <span><span class="ln dash"></span>→ ? dynamic (not statically resolvable)</span>
    <span>click: highlight wiring &middot; double-click: open source</span>
  </div>
  </div>
  <script nonce="${n}">${wiringMapScript(token)}
  </script>
</body>
</html>`;
  }
}
