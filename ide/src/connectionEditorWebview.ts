// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
//
// The connection editor webview's inline script, split out of connectionEditor.ts so it can be
// loaded without `vscode`. connectionEditor.ts builds the page and embeds this; the unit suite
// evaluates the SAME source in a jsdom page (webview-receivers.test.ts), so what the tests exercise
// is what ships.
import { SHAPE_HELPERS, WEBVIEW_GUARD_NOTE, embedJson, guardScript } from "./webviewMessaging";

/** What the connection editor's script is seeded with, each embedded as JSON. */
export interface ConnectionEditorScriptInputs {
  initial: unknown;
  routers: readonly string[];
  transports: readonly string[];
  fieldGroups: unknown;
  siblings: unknown;
  clone: boolean | undefined;
}

/** The whole inline `<script>` body for one render, guard included. `token` is this render's
 *  channel token, minted by the caller with the nonce (webviewMessaging.ts). */
export function connectionEditorScript(token: string, p: ConnectionEditorScriptInputs): string {
  return `
    const vscode = acquireVsCodeApi();${guardScript(token)}${SHAPE_HELPERS}
    const INITIAL = ${embedJson(p.initial)};
    const ROUTERS = ${embedJson(p.routers)};
    // The installed engine's transport list when it could be fetched, else the legacy constant.
    const TRANSPORTS = ${embedJson(p.transports)};
    // Grouped, typed field descriptors for the CURRENT transport/direction (connectionForm.ts), or
    // null when the engine could not describe them — see FormSchema. Recomputed extension-side on a
    // transport/direction change: the grouping rules live in one tested module, not duplicated here.
    let FIELD_GROUPS = ${embedJson(p.fieldGroups)};
    const SIBLINGS = ${embedJson(p.siblings)};
    const CLONE = ${embedJson(p.clone)};              // #175: create mode pre-filled from INITIAL, new name required
    const EDIT = INITIAL !== null && !CLONE;    // clone is NOT edit: name editable, no delete
    const $ = (id) => document.getElementById(id);
    const errorEl = $('error');

    // customEditor sibling picker: list every connection in the file + a "New connection" option, so
    // switching connections (or starting a new one) stays inside the one custom editor. A change posts
    // 'select' back to the provider, which re-renders the form for the chosen connection.
    if (SIBLINGS && Array.isArray(SIBLINGS.names)) {
      $('conn-picker-row').style.display = '';
      const sel = $('connPicker');
      { const o = document.createElement('option'); o.value = '\\u0000new'; o.textContent = '＋ New connection'; sel.appendChild(o); }
      for (const nm of SIBLINGS.names) { const o = document.createElement('option'); o.value = nm; o.textContent = nm; sel.appendChild(o); }
      sel.value = SIBLINGS.current == null ? '\\u0000new' : SIBLINGS.current;
      sel.addEventListener('change', () => {
        vscode.postMessage({ command: 'select', name: sel.value === '\\u0000new' ? null : sel.value });
      });
    }

    // populate selects
    for (const t of TRANSPORTS) { const o = document.createElement('option'); o.value = t; o.textContent = t; $('transport').appendChild(o); }
    { const blank = document.createElement('option'); blank.value = ''; blank.textContent = '(pick a router)'; $('router').appendChild(blank); }
    for (const r of ROUTERS) { const o = document.createElement('option'); o.value = r; o.textContent = r; $('router').appendChild(o); }

    function isInbound() { return $('direction').value === 'inbound'; }

    function settingRow(key, value, isEnv, cast) {
      const wrap = document.createElement('div'); wrap.className = 'setting';
      const k = document.createElement('input'); k.type = 'text'; k.className = 'k'; k.placeholder = 'key'; k.value = key || '';
      const v = document.createElement('input'); v.type = 'text'; v.placeholder = 'value'; v.value = value == null ? '' : String(value);
      const castSel = document.createElement('select');
      for (const c of ['', 'int', 'float', 'bool', 'str']) { const o = document.createElement('option'); o.value = c; o.textContent = c || 'cast'; castSel.appendChild(o); }
      castSel.value = cast || '';
      const envLabel = document.createElement('label'); envLabel.className = 'envbox';
      const envCb = document.createElement('input'); envCb.type = 'checkbox'; envCb.checked = !!isEnv;
      envLabel.appendChild(envCb); envLabel.appendChild(document.createTextNode('env()'));
      const del = document.createElement('button'); del.className = 'secondary'; del.textContent = '×';
      del.addEventListener('click', () => wrap.remove());
      function sync() { castSel.style.display = envCb.checked ? '' : 'none'; v.placeholder = envCb.checked ? 'env key' : 'value'; }
      envCb.addEventListener('change', sync); sync();
      wrap.append(k, v, envLabel, castSel, del);
      $('settings').appendChild(wrap);
    }

    // ----- schema-driven settings -----
    // One control per setting the ENGINE declares, grouped and typed (connectionForm.ts). Falls back
    // to the legacy free-text key/value rows when the engine could not describe itself, so an older
    // engine still edits connections. A field whose value the record carries but whose key the schema
    // does not describe arrives in its own group and is rendered here like any other -- never dropped.
    function renderField(f, into) {
      const wrap = document.createElement('div'); wrap.className = 'field';
      const lab = document.createElement('label');
      lab.textContent = f.label + (f.required ? ' *' : f.conditionallyRequired ? ' †' : '');
      lab.title = f.help || '';
      let control;
      const useEnv = f.isEnvRef || f.secretOnlyEnv;
      if (f.control === 'checkbox' && !useEnv) {
        control = document.createElement('input'); control.type = 'checkbox';
        control.checked = f.value === true || (f.value === undefined && f.defaultValue === true);
      } else if (f.control === 'select' && !useEnv) {
        control = document.createElement('select');
        for (const c of ['', ...(f.choices || [])]) {
          const o = document.createElement('option');
          o.value = String(c); o.textContent = c === '' ? '(default: ' + f.placeholder + ')' : String(c);
          control.appendChild(o);
        }
        control.value = f.value == null ? '' : String(f.value);
      } else {
        control = document.createElement('input');
        control.type = f.control === 'number' && !useEnv ? 'number' : 'text';
        control.placeholder = useEnv ? 'environment key' : (f.placeholder || '');
        const shown = useEnv ? (f.envKey || '') : f.value;
        control.value = shown == null ? '' : (typeof shown === 'object' ? JSON.stringify(shown) : String(shown));
      }
      control.dataset.key = f.key;
      control.dataset.kind = f.control;
      if (useEnv) { control.dataset.env = '1'; }
      if (f.cast) { control.dataset.cast = f.cast; }
      const hint = document.createElement('div'); hint.className = 'sub'; hint.textContent = f.help || '';
      wrap.append(lab, control, hint);
      into.appendChild(wrap);
    }

    function renderGroups(groups) {
      const host = $('settings'); host.innerHTML = '';
      for (const g of groups) {
        const box = document.createElement('details'); box.open = !g.collapsed;
        const sum = document.createElement('summary');
        sum.textContent = g.title + ' (' + g.fields.length + ')';
        if (g.description) { sum.title = g.description; }
        box.appendChild(sum);
        for (const f of g.fields) { renderField(f, box); }
        host.appendChild(box);
      }
    }

    /** Legacy path: the engine could not describe itself, so fall back to free-text key/value rows. */
    function prefillHints() {
      if (FIELD_GROUPS) { renderGroups(FIELD_GROUPS); return; }
      if (EDIT) return;
      $('settings').innerHTML = '';
      settingRow('', '', false, '');
    }

    /** Ask the extension to rebuild the descriptors when the transport or direction changes. */
    function requestFields() {
      if (!FIELD_GROUPS) { prefillHints(); return; }
      vscode.postMessage({
        command: 'fields',
        transport: $('transport').value,
        direction: $('direction').value,
        settings: collectSettings(),
      });
    }

    function refreshVisibility() {
      $('router-row').style.display = isInbound() ? '' : 'none';
      $('inbound-opts').style.display = isInbound() ? '' : 'none';
      $('outbound-opts').style.display = isInbound() ? 'none' : '';
    }

    // ----- load initial (edit / clone) or defaults (create) -----
    // Shared field pre-fill from INITIAL — everything except name/direction, which edit and clone set
    // differently (edit locks them; clone keeps direction editable and clears the name).
    function prefillFieldsFromInitial() {
      $('transport').value = INITIAL.transport;
      if (INITIAL.router) $('router').value = INITIAL.router;
      $('ackMode').value = INITIAL.ack_mode || '';
      $('strict').checked = !!INITIAL.strict;
      $('ordering').value = INITIAL.ordering || '';
      if (INITIAL.retry && INITIAL.retry.max_attempts != null) $('maxAttempts').value = String(INITIAL.retry.max_attempts);
      const s = INITIAL.settings || {};
      const keys = Object.keys(s);
      if (keys.length) {
        for (const key of keys) {
          const val = s[key];
          if (val && typeof val === 'object' && 'env' in val) settingRow(key, val.env, true, val.cast || '');
          else settingRow(key, val, false, '');
        }
      } else settingRow('', '', false, '');
    }
    if (EDIT) {
      $('title').textContent = 'Edit ' + INITIAL.name;
      $('direction').value = INITIAL.direction; $('direction').disabled = true;
      $('name').value = INITIAL.name; $('name').disabled = true;  // rename = remove + create
      prefillFieldsFromInitial();
      $('delete').style.display = '';
    } else if (CLONE && INITIAL) {
      // #175: pre-fill every field from the source connection but require a NEW name (Save = create).
      $('title').textContent = 'New Connection (clone of ' + INITIAL.name + ')';
      $('direction').value = INITIAL.direction;   // editable — a clone is a brand-new connection
      $('name').value = '';
      $('name').placeholder = 'new name (was ' + INITIAL.name + ')';
      prefillFieldsFromInitial();
      setTimeout(() => $('name').focus(), 0);
    } else {
      prefillHints();
    }
    refreshVisibility();

    $('direction').addEventListener('change', () => { refreshVisibility(); requestFields(); });
    $('transport').addEventListener('change', requestFields);
    $('addSetting').addEventListener('click', () => settingRow('', '', false, ''));

    function coerce(text) {
      if (text === 'true') return true;
      if (text === 'false') return false;
      if (/^-?\\d+$/.test(text)) return parseInt(text, 10);
      if (/^-?\\d*\\.\\d+$/.test(text)) return parseFloat(text);
      return text;
    }

    /**
     * The settings table the form currently expresses. Two shapes feed it: the schema-driven
     * controls (one per declared setting, keyed by data-key) and, when the engine could not describe
     * itself, the legacy free-text rows. An EMPTY control contributes no key at all — that is what
     * keeps "absent means this engine's default" true and stops a save writing the whole default set.
     */
    function collectSettings() {
      const settings = {};
      for (const el of document.querySelectorAll('#settings [data-key]')) {
        const key = el.dataset.key;
        if (!key) continue;
        if (el.dataset.env === '1') {
          const envKey = el.value.trim();
          if (!envKey) continue;              // a secret with no key set writes nothing
          const ref = { env: envKey };
          if (el.dataset.cast) ref.cast = el.dataset.cast;
          settings[key] = ref;
          continue;
        }
        if (el.dataset.kind === 'checkbox') {
          // A checkbox cannot say "untouched"; posting null lets the extension decide (see coerce).
          settings[key] = el.checked;
          continue;
        }
        const raw = el.value.trim();
        if (raw === '') continue;             // untouched -> omit the key entirely
        settings[key] = el.dataset.kind === 'table' ? coerce(raw) : coerce(raw);
      }
      for (const row of document.querySelectorAll('#settings .setting')) {
        const inputs = row.querySelectorAll('input[type=text]');
        const key = inputs[0].value.trim();
        if (!key) continue;
        const raw = inputs[1].value.trim();
        const envCb = row.querySelector('input[type=checkbox]');
        const castSel = row.querySelector('select');
        if (envCb.checked) {
          const ref = { env: raw };
          if (castSel.value) ref.cast = castSel.value;
          settings[key] = ref;
        } else {
          settings[key] = coerce(raw);
        }
      }
      return settings;
    }

    function build() {
      const direction = $('direction').value;
      const conn = { direction: direction, name: $('name').value.trim(), transport: $('transport').value };
      const settings = collectSettings();
      if (Object.keys(settings).length) conn.settings = settings;
      if (direction === 'inbound') {
        if ($('router').value) conn.router = $('router').value;
        if ($('ackMode').value) conn.ack_mode = $('ackMode').value;
        if ($('strict').checked) conn.strict = true;
      } else {
        if ($('ordering').value) conn.ordering = $('ordering').value;
        const ma = $('maxAttempts').value.trim();
        // BACKLOG #1217 half 2: "forever" (case-insensitive) is the connections.toml spelling of
        // retry-forever — it lands as [outbound.retry] max_attempts = "forever", which
        // connections_file.py's _coerce_retry_forever turns back into None at load. (The GLOBAL
        // default is a different file and a different key: messagefoundry.toml's
        // [delivery] retry_max_attempts, which this editor does not write.) parseInt('forever', 10)
        // is NaN, which would silently corrupt a word into a number here — write the word instead.
        // NOTE: no backticks anywhere in this block — it sits inside the outer template literal, so
        // a backtick here terminates it and tsc reports a bare "';' expected" two lines later.
        // Blank stays blank on purpose: it emits no retry table, so the connection inherits the
        // [delivery] default, which is FINITE. The field's hint says so; do not reword it to "forever".
        if (ma) conn.retry = { max_attempts: ma.toLowerCase() === 'forever' ? 'forever' : parseInt(ma, 10) };
      }
      return conn;
    }

    function validate(conn) {
      const need = [];
      if (!conn.name) need.push('name');
      if (conn.direction === 'inbound' && !conn.router) need.push('router');
      if (need.length) { errorEl.textContent = 'Required: ' + need.join(', ') + '.'; errorEl.style.display = ''; return false; }
      errorEl.style.display = 'none'; return true;
    }

    $('save').addEventListener('click', () => {
      const conn = build();
      if (!validate(conn)) return;
      vscode.postMessage({ command: 'save', conn: conn });
    });
    $('cancel').addEventListener('click', () => vscode.postMessage({ command: 'cancel' }));
    $('delete').addEventListener('click', () => vscode.postMessage({ command: 'delete', name: INITIAL.name }));

    // One entry per message its hosts post: at least connectionEditor.ts and configEditors.ts use
    // this page. Both post "error"; only connectionEditor.ts answers with "fields". A field is a
    // FieldDescriptor from connectionForm.ts: its declared fields with their types. The two
    // unknown-typed values (value, defaultValue) and the carried-through envDefault and
    // preserveValue are not typed there either. choices is required and may be null; envKey, cast
    // and a group's description may be absent and are never null.
    function mfFieldDescriptor(f) {
      return mfObj(f) && mfStr(f.key) && mfStr(f.label) && mfStr(f.control) && mfStr(f.type) &&
        mfStr(f.help) && mfBool(f.required) && mfBool(f.conditionallyRequired) && mfBool(f.secret) &&
        mfBool(f.envAllowed) && mfBool(f.secretOnlyEnv) && mfNullable(f.choices, Array.isArray) &&
        mfStr(f.placeholder) && mfBool(f.isEnvRef) && mfStr(f.group) && mfBool(f.known) &&
        mfBool(f.offDirection) && mfOpt(f.envKey, mfStr) && mfOpt(f.cast, mfStr);
    }
    const SHAPES = {
      error: (d) => mfStr(d.message),
      fields: (d) => mfArrOf(d.groups, (g) => mfObj(g) && mfStr(g.title) && mfBool(g.collapsed) &&
        mfOpt(g.description, mfStr) && mfArrOf(g.fields, mfFieldDescriptor)),
    };
    ${WEBVIEW_GUARD_NOTE}
    window.addEventListener('message', (e) => {
      const d = mfTrusted(e);
      if (!d || !mfShapeOk(d, 'command', SHAPES, 'connection editor')) { return; }
      if (d.command === 'error') { errorEl.textContent = d.message; errorEl.style.display = ''; }
      // Rebuilt descriptors after a transport/direction change. The grouping rules stay in the tested
      // module; the webview only draws what it is handed.
      if (d.command === 'fields') {
        FIELD_GROUPS = d.groups;
        renderGroups(FIELD_GROUPS);
      }
    });
  `;
}
