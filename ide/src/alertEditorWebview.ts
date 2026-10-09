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
    // True while a discarded list is the last word on the rules. See refuse().
    let refused = false;
    // True from an 'error' until the next list renders. The host posts 'error' for a failed add, a
    // failed remove and a failed re-read alike, and after the last two the rows may not match the
    // file. Remove names an ordinal, so it waits for the next list. A list carries no sequence, so
    // the page cannot tell one read before the error from one read after it.
    let unconfirmed = false;
    const REMOVE_OFF = 'Remove is off until the rules are read again: run the Alert Rules command again, or add a rule.';
    // True once a list has rendered. Until then the "No rules yet" note is the page's seed text,
    // not something read from the file.
    let listed = false;

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

    // True while rows are showing with Remove off. The line saying why is then the only reason on
    // the page, so no form message may take its place.
    function removeIsOff() { return unconfirmed && $('rows').querySelector('button') !== null; }
    function invalid(msg) { show(removeIsOff() ? msg + ' ' + REMOVE_OFF : msg); return false; }
    function validate(rule) {
      if (!rule.connection) { return invalid('Connection is required (use * for all).'); }
      for (const [k, label] of [['min_depth','Min depth'],['min_oldest_seconds','Min oldest'],['cooldown_seconds','Cooldown']]) {
        if (rule[k] !== undefined && !Number.isFinite(rule[k])) { return invalid(label + ' must be a number.'); }
      }
      if (removeIsOff()) { show(REMOVE_OFF); }
      // An error that arrived before any list rendered is all the page has to show under "Current
      // rules": the table and the note are both down. It stays until the host answers this Add.
      else if (!(unconfirmed && !listed)) { errorEl.style.display = 'none'; }
      return true;
    }
    // 'block', not '': the page's stylesheet hides .error, and clearing the inline value would hand
    // the element back to that rule, so the text would be set and never seen.
    function show(msg) { errorEl.textContent = msg; errorEl.style.display = 'block'; }

    // A list this panel cannot read. Every row goes, and with it every Remove: each is bound to a
    // rule ordinal, and the ordinals of a list nobody could read are not known. The "No rules yet"
    // note stays down, because it would be a claim about the file. Add goes off: it appends to a
    // first-match-wins list the operator cannot see. Close stays on. textContent (through show).
    function refuse(problem) {
      refused = true;
      $('rows').innerHTML = '';
      $('rules').style.display = 'none';
      $('empty').style.display = 'none';
      $('add').disabled = true;
      // Only a value in the file is the operator's to fix. A list that is not a list, an entry with
      // no ordinal, or a null (TOML has none) comes from the command that printed it, and no edit to
      // the file changes it. The quoting hint is given only for the case it fits.
      const todo = problem.inFile
        ? ' Fix that value in [[alerts.rules]] of the service-settings file' +
          (problem.quoted ? ' (a number must not be quoted)' : '') + ', then run the Alert Rules command again.'
        : ' No edit to the file fixes this: the command that lists the rules printed something this panel' +
          ' does not expect. Run the Alert Rules command again, and report it if this stays.';
      show('These rules cannot be shown. The list sent to this panel is malformed: ' + problem.text + '.' + todo +
        ' Remove and Add are off until a well-formed list arrives.');
    }

    function renderRules(rules) {
      listed = true;
      refused = false;
      unconfirmed = false;
      $('add').disabled = false;
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
        // The guard covers a button from an earlier render: refuse() takes it off the page, and a
        // click that still reached it must not post an ordinal from a list that was replaced.
        rm.addEventListener('click', () => { if (!refused && !unconfirmed) { vscode.postMessage({ command: 'remove', index: r.index }); } });
        tdBtn.appendChild(rm); tr.appendChild(tdBtn);
        tbody.appendChild(tr);
      }
    }

    $('add').addEventListener('click', () => {
      if (refused) return;
      const rule = build();
      if (!validate(rule)) return;
      vscode.postMessage({ command: 'add', rule });
    });
    $('close').addEventListener('click', () => vscode.postMessage({ command: 'cancel' }));

    // One entry per message the host posts (at least alertEditor.ts). A rule is one "alert list" row,
    // typed as the host's Rule: the ordinal is always there, and every other field may be absent but
    // has its declared type when present. None may be null, although Rule (alertEditor.ts) declares
    // "| null" on four of them: the row is a TOML table, TOML has no null, and so none is ever sent.
    // renderRules() still tests "== null", which is how it sees an absent field.
    // The three numerics are numbers. A hand-edited file can hold a quoted number, which the
    // engine's lax model loads; that row is not a Rule, so the list is discarded (BACKLOG #1123).
    const RULE_FIELDS = [
      ['event_type', mfStr, 'text'], ['connection', mfStr, 'text'], ['severity', mfStr, 'text'],
      ['min_depth', mfNum, 'a number'], ['min_oldest_seconds', mfNum, 'a number'],
      ['cooldown_seconds', mfNum, 'a number'], ['transports', (t) => mfArrOf(t, mfStr), 'a list of text'],
    ];
    // What is wrong with the first entry of a 'rules' message that is not a Rule, or null. It names
    // the rule by its ordinal, the field, and the kind of value found. Never the value. An entry
    // with no usable ordinal is named by its position, counted from 0 as the ordinals are. inFile
    // says whether the problem is a value in the file, the only kind the operator can fix; quoted
    // says it is a string where a number belongs.
    function rulesProblem(d) {
      const problem = (text, inFile, quoted) => ({ text: text, inFile: inFile, quoted: quoted });
      if (!Array.isArray(d.rules)) { return problem('the list is missing or is not a list', false, false); }
      // By index, not for-of or every(): a hole must be seen as an entry that is not a rule.
      for (let i = 0; i < d.rules.length; i++) {
        const r = d.rules[i];
        if (!mfObj(r)) { return problem('the entry at position ' + i + ' of the list is not a rule', false, false); }
        if (!mfInt(r.index)) {
          return problem('the entry at position ' + i + ' of the list has no whole-number index', false, false);
        }
        for (const [key, ok, want] of RULE_FIELDS) {
          const v = r[key];
          if (!mfOpt(v, ok)) {
            // A list is the right kind for transports, so "got list" would name no difference.
            const got = Array.isArray(v) && key === 'transports' ? 'a list with an entry that is not text' : mfKind(v);
            // A null did not come from the file, whether it is the value or sits inside a list.
            const hasNull = v === null || (Array.isArray(v) && v.indexOf(null) !== -1);
            return problem('rule ' + r.index + ', ' + key + ': expected ' + want + ', got ' + got,
              !hasNull, want === 'a number' && typeof v === 'string');
          }
        }
      }
      return null;
    }
    const SHAPES = {
      rules: (d) => rulesProblem(d) === null,
      error: (d) => mfStr(d.message),
    };
    ${WEBVIEW_GUARD_NOTE}
    window.addEventListener('message', (e) => {
      const d = mfTrusted(e);
      if (!d) { return; }
      if (!mfShapeOk(d, 'command', SHAPES, 'Alert Rules')) {
        // A discarded list is shown as well as warned, and the page stops acting on the old one.
        // rulesProblem() runs again here, as stateProblem() does in the Security Settings page: the
        // shape entry stays a pure check, and the second walk happens only for a discarded list.
        const problem = d.command === 'rules' ? rulesProblem(d) : null;
        if (problem !== null) { refuse(problem); }
        return;
      }
      if (d.command === 'rules') { renderRules(d.rules); errorEl.style.display = 'none'; }
      // After a refusal the rows are still gone. The error is the newer fact, so it is shown in the
      // refusal's place, with the reason the page is still off.
      else if (d.command === 'error') {
        if (refused) {
          show(d.message + ' The rules are still not shown. Remove and Add stay off until a well-formed list arrives.');
          return;
        }
        unconfirmed = true;
        // Before any list has rendered, "No rules yet" is seed text and would stand beside this
        // error as a claim about a file nobody read.
        if (!listed) { $('empty').style.display = 'none'; }
        const stale = $('rows').querySelectorAll('button');
        for (let i = 0; i < stale.length; i++) { stale[i].disabled = true; }
        show(stale.length === 0 ? d.message : d.message + ' ' + REMOVE_OFF);
      }
    });
  `;
}
