// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
//
// The Alert Rules webview's inline script, split out of alertEditor.ts so it can be loaded without
// `vscode`. alertEditor.ts builds the page and embeds this; the unit suite evaluates the SAME
// source in a jsdom page (webview-receivers.test.ts), so what the tests exercise is what ships.
import { SHAPE_HELPERS, WEBVIEW_GUARD_NOTE, SCRIPT_STARTED_MARK, embedJson, guardScript } from "./webviewMessaging";

/** The whole inline `<script>` body for one render, guard included. `token` is this render's
 *  channel token, minted by the caller with the nonce (webviewMessaging.ts). */
export function alertEditorScript(
  token: string,
  eventTypes: readonly string[],
  severities: readonly string[],
): string {
  return `
    const vscode = acquireVsCodeApi();${SCRIPT_STARTED_MARK}${guardScript(token)}${SHAPE_HELPERS}
    const EVENT_TYPES = ${embedJson(eventTypes)};
    const SEVERITIES = ${embedJson(severities)};
    const $ = (id) => document.getElementById(id);
    const errorEl = $('error');

    for (const t of EVENT_TYPES) { const o = document.createElement('option'); o.value = t; o.textContent = t; $('event_type').appendChild(o); }
    for (const s of SEVERITIES) { const o = document.createElement('option'); o.value = s; o.textContent = s; $('severity').appendChild(o); }
    $('severity').value = 'warning';

    function transportsValue(sel) {
      switch (sel) {
        case 'webhook': return ['webhook'];
        case 'email': return ['email'];
        case 'both': return ['webhook', 'email'];
        case 'suppress': return [];        // [] = suppress
        default: return undefined;          // omit = all configured
      }
    }
    function transportsLabel(t) {
      if (t === undefined || t === null) return 'all';
      if (t.length === 0) return 'suppress';
      return t.join(', ');
    }
    const num = (id) => { const v = $(id).value.trim(); return v === '' ? undefined : Number(v); };

    function build() {
      const rule = {
        event_type: $('event_type').value,
        connection: $('connection').value.trim(),
        severity: $('severity').value,
      };
      const d = num('min_depth'); if (d !== undefined) rule.min_depth = d;
      const a = num('min_oldest_seconds'); if (a !== undefined) rule.min_oldest_seconds = a;
      const c = num('cooldown_seconds'); if (c !== undefined) rule.cooldown_seconds = c;
      const t = transportsValue($('transports').value); if (t !== undefined) rule.transports = t;
      return rule;
    }

    function validate(rule) {
      if (!rule.connection) { show('Connection is required (use * for all).'); return false; }
      for (const [k, label] of [['min_depth','Min depth'],['min_oldest_seconds','Min oldest'],['cooldown_seconds','Cooldown']]) {
        if (rule[k] !== undefined && !Number.isFinite(rule[k])) { show(label + ' must be a number.'); return false; }
      }
      errorEl.style.display = 'none';
      return true;
    }
    function show(msg) { errorEl.textContent = msg; errorEl.style.display = ''; }

    function renderRules(rules) {
      const tbody = $('rows');
      tbody.innerHTML = '';
      $('empty').style.display = rules.length ? 'none' : '';
      $('rules').style.display = rules.length ? '' : 'none';
      for (const r of rules) {
        const tr = document.createElement('tr');
        const cells = [
          r.index,
          r.event_type || 'any',
          r.connection || '*',
          r.min_depth == null ? '' : r.min_depth,
          r.min_oldest_seconds == null ? '' : r.min_oldest_seconds,
          r.severity || 'warning',
          transportsLabel(r.transports),
          r.cooldown_seconds == null ? '' : r.cooldown_seconds,
        ];
        cells.forEach((text, i) => { const td = document.createElement('td'); if (i === 0) td.className = 'idx'; td.textContent = String(text); tr.appendChild(td); });
        const tdBtn = document.createElement('td');
        const rm = document.createElement('button'); rm.className = 'rm'; rm.textContent = 'Remove';
        rm.addEventListener('click', () => vscode.postMessage({ command: 'remove', index: r.index }));
        tdBtn.appendChild(rm); tr.appendChild(tdBtn);
        tbody.appendChild(tr);
      }
    }

    $('add').addEventListener('click', () => {
      const rule = build();
      if (!validate(rule)) return;
      vscode.postMessage({ command: 'add', rule });
    });
    $('close').addEventListener('click', () => vscode.postMessage({ command: 'cancel' }));

    // One entry per message the host posts (at least alertEditor.ts). A rule is one "alert list" row: the
    // ordinal is always there, and every AlertRule field is optional but typed when present. The row
    // is the raw TOML table, and the engine's lax model loads a quoted number (and a boolean) for the
    // three numeric fields, so any scalar passes there: the engine accepts that file, and this table
    // only shows the value. A table or array is refused.
    function mfNumeric(x) { return mfNum(x) || mfStr(x) || mfBool(x); }
    const SHAPES = {
      rules: (d) => mfArrOf(d.rules, (r) => mfObj(r) && mfInt(r.index) &&
        mfOpt(r.event_type, mfStr) && mfOpt(r.connection, mfStr) && mfOpt(r.severity, mfStr) &&
        mfOpt(r.min_depth, mfNumeric) && mfOpt(r.min_oldest_seconds, mfNumeric) &&
        mfOpt(r.cooldown_seconds, mfNumeric) && mfOpt(r.transports, (t) => mfArrOf(t, mfStr))),
      error: (d) => mfStr(d.message),
    };
    ${WEBVIEW_GUARD_NOTE}
    window.addEventListener('message', (e) => {
      const d = mfTrusted(e);
      if (!d || !mfShapeOk(d, 'command', SHAPES, 'Alert Rules')) { return; }
      if (d.command === 'rules') { renderRules(d.rules); errorEl.style.display = 'none'; }
      else if (d.command === 'error') { show(d.message); }
    });
  `;
}
