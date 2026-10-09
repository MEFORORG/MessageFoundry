// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
//
// The Wiring Map webview's inline script, split out of wiringMap.ts so it can be loaded without
// `vscode`. wiringMap.ts builds the page and embeds this; the unit suite evaluates the SAME source
// in a jsdom page (webview-receivers.test.ts), so what the tests exercise is what ships.
import { SHAPE_HELPERS, WEBVIEW_GUARD_NOTE, guardScript } from "./webviewMessaging";

/** The whole inline `<script>` body for one render, guard included. `token` is this render's
 *  channel token, minted by the caller with the nonce (webviewMessaging.ts). */
export function wiringMapScript(token: string): string {
  return `
    const vscode = acquireVsCodeApi();${guardScript(token)}${SHAPE_HELPERS}
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

    // The one message the host posts: WiringMapPayload (wiringMapModel.ts). map and focus are
    // required and may be null; a node's port, open and stub may be absent and are never null.
    function mfElementRef(r) { return mfObj(r) && mfStr(r.kind) && mfStr(r.name); }
    function mfMapNode(nd) {
      return mfObj(nd) && mfStr(nd.kind) && mfStr(nd.name) && mfInt(nd.row) && mfBool(nd.dynamic) &&
        mfOpt(nd.port, mfStr) && mfOpt(nd.stub, mfBool) &&
        mfOpt(nd.open, (o) => mfObj(o) && mfStr(o.file) && mfInt(o.line));
    }
    function mfMapEdge(e) {
      return mfObj(e) && mfStr(e.fromKind) && mfStr(e.from) && mfStr(e.toKind) && mfStr(e.to) &&
        mfStr(e.provenance);
    }
    const SHAPES = {
      map: (m) => mfArrOf(m.names, mfElementRef) && mfNullable(m.focus, mfElementRef) &&
        mfNullable(m.map, (w) => mfObj(w) && mfBool(w.truncated) && mfBool(w.focusMissing) &&
          Array.isArray(w.columns) && w.columns.length === 4 &&
          mfArrOf(w.columns, (c) => mfArrOf(c, mfMapNode)) && mfArrOf(w.edges, mfMapEdge)),
    };
    ${WEBVIEW_GUARD_NOTE}
    window.addEventListener('message', (ev) => {
      const m = mfTrusted(ev);
      if (!m || !mfShapeOk(m, 'type', SHAPES, 'Wiring Map')) { return; }
      if (m.type === 'map') { state = m; render(); }
    });
    vscode.postMessage({ command: 'ready' });
  `;
}
