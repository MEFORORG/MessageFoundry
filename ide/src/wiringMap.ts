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
import { buildWiringMap, MAX_HOPS, type MapFocus } from "./wiringMapModel";
import type { GraphProvider } from "./graphTree";

type Incoming =
  | { command: "ready" }
  | { command: "setFocus"; kind: ElementKind; name: string }
  | { command: "refresh" }
  | { command: "open"; file: string; line: number }
  | { command: "reveal"; kind: ElementKind; name: string };

function nonce(): string {
  let s = "";
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  for (let i = 0; i < 24; i++) {
    s += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return s;
}

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
    this.panel.webview.html = this.html();
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
    const g = this.graph.getGraph();
    const map = g ? buildWiringMap(g, this.focus, MAX_HOPS) : null;
    const names: { kind: ElementKind; name: string }[] = [];
    if (g) {
      for (const c of g.inbound) {
        names.push({ kind: "inbound", name: c.name });
      }
      for (const r of g.routers) {
        names.push({ kind: "router", name: r.name });
      }
      for (const h of g.handlers) {
        names.push({ kind: "handler", name: h.name });
      }
      for (const o of g.outbound) {
        names.push({ kind: "outbound", name: o.name });
      }
    }
    void this.panel.webview.postMessage({
      type: "map",
      map,
      focus: this.focus,
      names,
    });
  }

  private html(): string {
    const n = nonce();
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
  </style>
</head>
<body>
  <div class="bar">
    <span class="focuslbl" id="focusLbl" title="Current focus element"></span>
    <input id="search" list="elementNames" placeholder="Jump to an element…" />
    <datalist id="elementNames"></datalist>
    <button id="refresh" title="Re-read the wiring graph">Refresh</button>
    <button id="reveal" disabled title="Reveal the selected node in the Connections tree">Reveal in tree</button>
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
  <script nonce="${n}">
    const vscode = acquireVsCodeApi();
    const SVGNS = 'http://www.w3.org/2000/svg';
    const KINDS = ['inbound', 'router', 'handler', 'outbound'];
    const HEADERS = ['INBOUND', 'ROUTERS', 'HANDLERS', 'OUTBOUND'];
    // Vertical layout: the four pipeline stages stack as top→bottom bands (inbound at the top,
    // outbound at the bottom); nodes within a band spread horizontally by their model row. HSTEP is
    // the horizontal step between sibling nodes in a band; BANDSTEP the vertical step between bands.
    const NODEW = 200, NODEH = 36, HSTEP = 232, BANDSTEP = 84, TOP = 26, LEFT = 12;
    let state = null;      // last posted { map, focus, names }
    let selected = null;   // { kind, name } of the selected node

    const focusLbl = document.getElementById('focusLbl');
    const search = document.getElementById('search');
    const datalist = document.getElementById('elementNames');
    const note = document.getElementById('note');
    const canvas = document.getElementById('canvas');
    const revealBtn = document.getElementById('reveal');

    function el(tag, attrs, parent) {
      const e = document.createElementNS(SVGNS, tag);
      for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, v);
      if (parent) parent.appendChild(e);
      return e;
    }

    function bandTop(i) { return TOP + i * BANDSTEP; }
    function nodeXY(node) {
      return { x: LEFT + node.row * HSTEP, y: bandTop(KINDS.indexOf(node.kind)) };
    }

    function trimmed(s, max) { return s.length > max ? s.slice(0, max - 1) + '…' : s; }

    function render() {
      canvas.textContent = '';
      note.textContent = '';
      note.classList.remove('warn');
      if (!state) return;
      const { map, focus } = state;
      focusLbl.textContent = '';
      if (focus) {
        const k = document.createElement('span');
        k.className = 'kind';
        k.textContent = focus.kind;
        focusLbl.appendChild(k);
        focusLbl.appendChild(document.createTextNode(focus.name));
        focusLbl.title = focus.kind + ' ' + focus.name;
      }
      datalist.textContent = '';
      for (const e of state.names) {
        const o = document.createElement('option');
        o.value = e.kind + ': ' + e.name;
        datalist.appendChild(o);
      }
      if (!map) { note.textContent = 'No wiring graph loaded — open a MessageFoundry workspace and Refresh.'; return; }
      if (map.focusMissing) {
        note.classList.add('warn');
        note.textContent = 'The focused element no longer exists in the graph — pick another element above.';
        return;
      }
      if (map.truncated) {
        note.classList.add('warn');
        note.textContent = 'Map truncated at 150 nodes (farthest neighbors dropped) — focus on a specific element to narrow it.';
      }
      const byId = new Map();
      for (const col of map.columns) for (const nd of col) byId.set(nd.kind + ':' + nd.name, nd);
      const perBand = Math.max(1, ...map.columns.map((c) => c.length));
      const width = LEFT * 2 + (perBand - 1) * HSTEP + NODEW;
      const height = bandTop(KINDS.length - 1) + NODEH + 14;
      const svg = el('svg', { width, height, viewBox: '0 0 ' + width + ' ' + height });

      // A stage label sits just above each band's row of nodes.
      HEADERS.forEach((h, i) => {
        const t = el('text', { x: LEFT, y: bandTop(i) - 7, class: 'colhead' }, svg);
        t.textContent = h;
      });

      // Edges first (under the nodes). The pipeline flows top→bottom: a forward edge leaves the
      // source's bottom edge and enters the target's top; the legal handler→inbound pass-through
      // back-edge runs the other way (leaves the top, lands on the target's bottom).
      const edgeEls = [];
      for (const e of map.edges) {
        const from = byId.get(e.fromKind + ':' + e.from);
        const to = byId.get(e.toKind + ':' + e.to);
        if (!from || !to) continue;
        const a = nodeXY(from), b = nodeXY(to);
        const forward = KINDS.indexOf(to.kind) > KINDS.indexOf(from.kind);
        const x1 = a.x + NODEW / 2, x2 = b.x + NODEW / 2;
        const y1 = forward ? a.y + NODEH : a.y;
        const y2 = forward ? b.y : b.y + NODEH;
        const dy = Math.max(28, Math.abs(y2 - y1) / 2) * (forward ? 1 : -1);
        const path = el('path', {
          d: 'M ' + x1 + ' ' + y1 + ' C ' + x1 + ' ' + (y1 + dy) + ', ' + x2 + ' ' + (y2 - dy) + ', ' + x2 + ' ' + y2,
          class: 'edge p-' + e.provenance,
        }, svg);
        const t = el('title', {}, path);
        t.textContent = e.fromKind + ' ' + e.from + ' → ' + e.toKind + ' ' + e.to + ' (' + e.provenance + ')';
        edgeEls.push({ e, path });
      }

      // Nodes.
      const nodeEls = [];
      for (const col of map.columns) {
        for (const nd of col) {
          const { x, y } = nodeXY(nd);
          const isFocus = focus && !nd.stub && nd.kind === focus.kind && nd.name === focus.name;
          const g = el('g', {
            class: 'node k-' + nd.kind + (nd.stub ? ' stub' : '') + (isFocus ? ' focus' : ''),
            transform: 'translate(' + x + ',' + y + ')',
          }, svg);
          if (nd.stub) {
            el('rect', { class: 'box', width: 34, height: NODEH, x: 0, y: 0 }, g);
            const q = el('text', { class: 'name', x: 17, y: NODEH / 2 + 4, 'text-anchor': 'middle' }, g);
            q.textContent = '?';
            const t = el('title', {}, g);
            t.textContent = 'Dynamic — target not statically resolvable';
          } else {
            el('rect', { class: 'box', width: NODEW, height: NODEH, x: 0, y: 0 }, g);
            el('rect', { class: 'accent', width: 3, height: NODEH, x: 0, y: 0 }, g);
            const glyph = nd.kind === 'inbound' ? '→ ' : nd.kind === 'outbound' ? '↥ ' : '';
            const name = el('text', { class: 'name', x: 10, y: nd.port || nd.dynamic ? 15 : NODEH / 2 + 4 }, g);
            name.textContent = glyph + trimmed(nd.name, 26);
            const subText = [nd.port ? ':' + nd.port : '', nd.dynamic ? 'dynamic' : ''].filter(Boolean).join(' · ');
            if (subText) {
              const sub = el('text', { class: 'sub', x: 10, y: 29 }, g);
              sub.textContent = subText;
            }
            const t = el('title', {}, g);
            t.textContent = nd.kind + ' ' + nd.name + (nd.port ? ' :' + nd.port : '') + (nd.dynamic ? ' (dynamic)' : '');
          }
          g.addEventListener('click', () => select(nd));
          if (!nd.stub && nd.open) {
            g.addEventListener('dblclick', () =>
              vscode.postMessage({ command: 'open', file: nd.open.file, line: nd.open.line }));
          }
          nodeEls.push({ nd, g });
        }
      }
      canvas.appendChild(svg);

      function select(nd) {
        selected = nd.stub ? null : { kind: nd.kind, name: nd.name };
        revealBtn.disabled = !selected;
        const key = nd.kind + ':' + nd.name;
        const incident = new Set([key]);
        for (const { e, path } of edgeEls) {
          const hit = (e.fromKind + ':' + e.from) === key || (e.toKind + ':' + e.to) === key;
          path.classList.toggle('hi', hit);
          path.classList.toggle('dim', !hit);
          if (hit) { incident.add(e.fromKind + ':' + e.from); incident.add(e.toKind + ':' + e.to); }
        }
        for (const { nd: other, g } of nodeEls) {
          g.classList.toggle('selected', other === nd);
          g.classList.toggle('dim', !incident.has(other.kind + ':' + other.name));
        }
      }
      // Re-apply a still-valid selection across re-renders.
      if (selected) {
        const keep = nodeEls.find(({ nd }) => !nd.stub && nd.kind === selected.kind && nd.name === selected.name);
        if (keep) select(keep.nd); else { selected = null; revealBtn.disabled = true; }
      } else {
        revealBtn.disabled = true;
      }
    }

    document.getElementById('refresh').addEventListener('click', () => vscode.postMessage({ command: 'refresh' }));
    revealBtn.addEventListener('click', () => {
      if (selected) vscode.postMessage({ command: 'reveal', kind: selected.kind, name: selected.name });
    });
    search.addEventListener('change', () => {
      const v = search.value.trim();
      if (!v || !state) return;
      let hit = null;
      const m = v.match(/^(inbound|router|handler|outbound):\\s*(.+)$/);
      if (m) hit = state.names.find((e) => e.kind === m[1] && e.name === m[2]);
      if (!hit) hit = state.names.find((e) => e.name === v);
      if (hit) {
        search.value = '';
        vscode.postMessage({ command: 'setFocus', kind: hit.kind, name: hit.name });
      }
    });

    window.addEventListener('message', (ev) => {
      const m = ev.data;
      if (m && m.type === 'map') { state = m; render(); }
    });
    vscode.postMessage({ command: 'ready' });
  </script>
</body>
</html>`;
  }
}
