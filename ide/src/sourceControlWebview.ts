// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
//
// The config-repo storage webview's inline script, split out of sourceControl.ts so it can be
// loaded without `vscode`. sourceControl.ts builds the page and embeds this; the unit suite
// evaluates the SAME source in a jsdom page (webview-receivers.test.ts), so what the tests exercise
// is what ships.
import { SHAPE_HELPERS, WEBVIEW_GUARD_NOTE, SCRIPT_STARTED_MARK, guardScript } from "./webviewMessaging";

/** The whole inline `<script>` body for one render, guard included. `token` is this render's
 *  channel token, minted by the caller with the nonce (webviewMessaging.ts). */
export function sourceControlScript(token: string): string {
  return `
    const vscode = acquireVsCodeApi();${SCRIPT_STARTED_MARK}${guardScript(token)}${SHAPE_HELPERS}
    const url = document.getElementById('url');
    const err = document.getElementById('err');
    function mode() { return document.querySelector('input[name=mode]:checked').value; }
    function sync() { const remote = mode() === 'remote'; url.disabled = !remote; if (remote) url.focus(); }
    document.querySelectorAll('input[name=mode]').forEach(function (r) {
      r.addEventListener('change', function () { err.textContent = ''; sync(); });
    });
    document.getElementById('save').addEventListener('click', function () {
      err.textContent = '';
      vscode.postMessage({ command: 'save', mode: mode(), url: url.value });
    });
    document.getElementById('cancel').addEventListener('click', function () {
      vscode.postMessage({ command: 'cancel' });
    });
    // The one message the host posts (sourceControl.ts).
    const SHAPES = { error: function (d) { return mfStr(d.text); } };
    ${WEBVIEW_GUARD_NOTE}
    window.addEventListener('message', function (e) {
      const d = mfTrusted(e);
      if (!d || !mfShapeOk(d, 'command', SHAPES, 'config repo storage')) { return; }
      if (d.command === 'error') { err.textContent = d.text; }
    });
    sync();
  `;
}
