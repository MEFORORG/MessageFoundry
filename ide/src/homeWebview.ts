// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
//
// The Home view webview's inline script, split out of home.ts so it can be loaded without `vscode`.
// home.ts builds the page and embeds this; the unit suite evaluates the SAME source in a jsdom page
// (webview-receivers.test.ts), so what the tests exercise is what ships.
import { SHAPE_HELPERS, WEBVIEW_GUARD_NOTE, guardScript } from "./webviewMessaging";

/** The whole inline `<script>` body for one render, guard included. `token` is this render's
 *  channel token, minted by the caller with the nonce (webviewMessaging.ts). */
export function homeScript(token: string): string {
  return `
    const vscode = acquireVsCodeApi();${guardScript(token)}${SHAPE_HELPERS}
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
    // The one message the host posts (home.ts).
    const SHAPES = { setFilter: (d) => mfStr(d.text) };
    ${WEBVIEW_GUARD_NOTE}
    window.addEventListener('message', (e) => {
      const d = mfTrusted(e);
      if (!d || !mfShapeOk(d, 'command', SHAPES, 'Home')) { return; }
      if (d.command === 'setFilter' && d.text !== search.value) {
        search.value = d.text;
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
  `;
}
