// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
//
// The connection editor webview's inline script, split out of connectionEditor.ts so it can be
// loaded without `vscode`. connectionEditor.ts builds the page and embeds this; the unit suite
// evaluates the SAME source in a jsdom page (webview-receivers.test.ts), so what the tests exercise
// is what ships.
import { ENVREF_KEY_NAMES, FIELD_CONTROLS, PARAM_TYPES } from "./connectionForm";
import { SHAPE_HELPERS, WEBVIEW_GUARD_NOTE, SCRIPT_STARTED_MARK, embedJson, guardScript } from "./webviewMessaging";

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
    const vscode = acquireVsCodeApi();${SCRIPT_STARTED_MARK}${guardScript(token)}${SHAPE_HELPERS}
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

    // The {env = "KEY"} inline table, and nothing else: a non-empty string env key, and no key outside
    // the list envRefOf in connectionForm.ts uses, embedded from there. So a table-valued setting
    // that happens to carry an "env" key is a table here too, not a reference (BACKLOG #5565).
    const ENVREF_KEY_NAMES = ${embedJson(ENVREF_KEY_NAMES)};
    function isEnvRefValue(val) {
      if (!val || typeof val !== 'object' || Array.isArray(val)) return false;
      if (typeof val.env !== 'string' || val.env === '') return false;
      return Object.keys(val).every((k) => ENVREF_KEY_NAMES.includes(k));
    }

    // A value as a text input shows it: a table or array as JSON, never String(value), which shows
    // and saves '[object Object]' (BACKLOG #5565).
    function displayValue(value) {
      return value == null ? '' : (typeof value === 'object' ? JSON.stringify(value) : String(value));
    }

    // A legacy row drawn from the record keeps the record's value here, so an untouched row saves
    // that value exactly (a table, an env reference's default, a string of digits) rather than what
    // the free text re-parses to.
    const ROW_ORIGINAL = new WeakMap();

    function settingRow(key, value, isEnv, cast, original) {
      const wrap = document.createElement('div'); wrap.className = 'setting';
      const k = document.createElement('input'); k.type = 'text'; k.className = 'k'; k.placeholder = 'key'; k.value = key || '';
      const v = document.createElement('input'); v.type = 'text'; v.placeholder = 'value';
      v.value = displayValue(value);
      // "Untouched" is judged against what the input holds after the assignment, not the recorded
      // text: a text input strips CR and LF, so a multi-line value never compared equal and was
      // saved without its line breaks.
      if (original !== undefined) ROW_ORIGINAL.set(wrap, { key: k.value, shown: v.value, isEnv: !!isEnv, cast: cast || '', original: original });
      // Marked, so the save parses the JSON back into the table.
      if (value !== null && typeof value === 'object') v.dataset.table = '1';
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
    // Each schema control keeps its descriptor here, so the save can apply the field's type and
    // default, write back an untouched control's recorded value exactly, and write back what the
    // field holds but never shows: an inline credential (preserveValue) and an env reference's
    // default (envDefault). Kept here rather than in a data- attribute or an input, so no control
    // displays the credential. It is not kept out of the page: INITIAL and FIELD_GROUPS carry it.
    const HELD = new WeakMap();
    // What each control showed right after it was drawn: an untouched control still shows exactly
    // this, whatever the browser did to the value on assignment (a text input strips CR and LF).
    const SHOWN = new WeakMap();
    // The record's inline credentials (HELD_SECRETS) and secret env references' inline defaults
    // (HELD_DEFAULTS), by key. A transport or direction change sends the host HELD_MARK in their
    // place, never the value: the host rebuilds the fields from what it is sent, so the key (and an
    // off-direction secret's field) survives the round trip, and a key the new schema does not
    // declare comes back showing the mark rather than the credential. The save swaps the value back.
    const HELD_MARK = '[held inline credential, not shown]';
    const HELD_SECRETS = new Map();
    const HELD_DEFAULTS = new Map();
    // Keys whose inline credential the user chose to remove; the save then writes no value for them.
    const REMOVED_SECRETS = new Set();
    function heldSecret(f) {
      if (REMOVED_SECRETS.has(f.key)) return undefined;
      if (f.preserveValue !== undefined && f.preserveValue !== HELD_MARK) return f.preserveValue;
      return f.secretOnlyEnv || f.preserveValue === HELD_MARK ? HELD_SECRETS.get(f.key) : undefined;
    }
    function renderField(f, into) {
      const wrap = document.createElement('div'); wrap.className = 'field';
      const lab = document.createElement('label');
      lab.textContent = f.label + (f.required ? ' *' : f.conditionallyRequired ? ' †' : '');
      lab.title = f.help || '';
      if (f.preserveValue !== undefined && f.preserveValue !== HELD_MARK) HELD_SECRETS.set(f.key, f.preserveValue);
      if (f.secret && f.envDefault !== undefined && f.envDefault !== HELD_MARK) HELD_DEFAULTS.set(f.key, f.envDefault);
      let control;
      const useEnv = f.isEnvRef || f.secretOnlyEnv;
      // A checkbox only while the recorded value is a boolean: a checkbox would read any other value
      // as false, and an untouched save would write false in its place (a "yes" the engine refuses
      // at load becoming a setting it accepts). Any other value gets a text box, saved back as it is.
      const boolish = f.value === undefined || f.value === null || typeof f.value === 'boolean';
      if (f.control === 'checkbox' && !useEnv && boolish) {
        control = document.createElement('input'); control.type = 'checkbox';
        control.checked = f.value === true || (f.value === undefined && f.defaultValue === true);
      } else if (f.control === 'select' && !useEnv) {
        control = document.createElement('select');
        const choices = f.choices || [];
        const options = ['', ...choices];
        // A recorded value outside the choices gets its own option, so it shows and an untouched
        // save keeps it, rather than the select going blank and the save dropping the key.
        if (f.value != null && !choices.some((c) => String(c) === displayValue(f.value))) options.push(f.value);
        for (const c of options) {
          const o = document.createElement('option');
          o.value = displayValue(c); o.textContent = c === '' ? '(default: ' + f.placeholder + ')' : displayValue(c);
          control.appendChild(o);
        }
        control.value = displayValue(f.value);
      } else {
        control = document.createElement('input');
        // A number box only while the recorded value is a number: the browser blanks any other
        // value a number box is given, and the save would then drop the key.
        const numeric = f.value === undefined || f.value === null || typeof f.value === 'number';
        control.type = f.control === 'number' && !useEnv && numeric ? 'number' : 'text';
        control.placeholder = useEnv ? secretHint(f) : (f.placeholder || '');
        control.value = displayValue(useEnv ? (f.envKey || '') : f.value);
      }
      control.dataset.key = f.key;
      control.dataset.kind = f.control === 'checkbox' && !boolish ? 'text' : f.control;
      if (useEnv) { control.dataset.env = '1'; }
      if (f.cast) { control.dataset.cast = f.cast; }
      HELD.set(control, f);
      SHOWN.set(control, control.value);
      const hint = document.createElement('div'); hint.className = 'sub'; hint.textContent = f.help || '';
      wrap.append(lab, control);
      // An inline credential the form holds can be removed, as the legacy row's delete allowed:
      // leaving the box blank otherwise writes it back. A clone never copies it, so needs no button.
      if (useEnv && !CLONE && heldSecret(f) !== undefined) {
        const remove = document.createElement('button'); remove.className = 'secondary';
        remove.dataset.removeSecret = f.key;
        remove.textContent = 'Remove the inline value';
        remove.addEventListener('click', () => {
          if (REMOVED_SECRETS.has(f.key)) REMOVED_SECRETS.delete(f.key); else REMOVED_SECRETS.add(f.key);
          remove.textContent = REMOVED_SECRETS.has(f.key) ? 'Keep the inline value' : 'Remove the inline value';
          control.placeholder = secretHint(f);
        });
        wrap.append(remove);
      }
      wrap.append(hint);
      into.appendChild(wrap);
    }

    function secretHint(f) {
      if (REMOVED_SECRETS.has(f.key)) return 'environment key (the inline value will be removed)';
      if (heldSecret(f) === undefined) return 'environment key';
      return CLONE
        ? 'environment key (the inline value is not copied to a clone)'
        : 'environment key (the current inline value is kept, not shown)';
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
        settings: collectSettings(true),
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
      // The settings: the schema-driven controls whenever the engine described itself (BACKLOG
      // #5565). The host built FIELD_GROUPS from this very record, so they already carry its values,
      // with a secret held back rather than shown and a table as JSON. The free-text rows below are
      // only the fallback for an engine that could not describe itself.
      if (FIELD_GROUPS) { renderGroups(FIELD_GROUPS); return; }
      const s = INITIAL.settings || {};
      const keys = Object.keys(s);
      if (keys.length) {
        for (const key of keys) {
          const val = s[key];
          if (isEnvRefValue(val)) settingRow(key, val.env, true, val.cast || '', val);
          else settingRow(key, val, false, '', val);
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

    // A table or array typed as JSON parses back to its value; text that does not parse is returned
    // verbatim, so the engine's validator refuses what the user typed rather than this page guessing
    // (the rule coerce in connectionForm.ts states for a table).
    function parseTable(text) {
      try { return JSON.parse(text); } catch (e) { return text; }
    }

    // Edited text for a schema field, read by the field's declared type, as coerce in
    // connectionForm.ts reads it: a table, or a value the record held as a table, parses as JSON; a
    // select takes the matching choice with its JSON type; a number or a bool is converted when the
    // text is one; anything else, and text that does not convert, is posted verbatim, so the
    // engine's validator refuses what the user typed rather than this page guessing.
    function typedValue(f, raw) {
      if (f.control === 'table' || (f.value !== null && typeof f.value === 'object')) return parseTable(raw);
      if (f.control === 'select') {
        const hit = (f.choices || []).find((c) => String(c) === raw);
        return hit !== undefined ? hit : raw;
      }
      if (f.type === 'int' || f.type === 'float') { const n = Number(raw); return Number.isFinite(n) ? n : raw; }
      if (f.type === 'bool') return raw === 'true' ? true : raw === 'false' ? false : raw;
      return raw;
    }

    /**
     * The settings table the form currently expresses. Two shapes feed it: the schema-driven
     * controls (one per declared setting, keyed by data-key) and, when the engine could not describe
     * itself, the legacy free-text rows. An EMPTY control contributes no key at all — that is what
     * keeps "absent means this engine's default" true and stops a save writing the whole default set.
     * An UNTOUCHED control drawn from the record writes the recorded value back exactly. forHost
     * is a transport or direction change's request: a held inline credential, or a secret env
     * reference's inline default, goes in it only as HELD_MARK, never as the value.
     */
    function collectSettings(forHost) {
      const settings = {};
      for (const el of document.querySelectorAll('#settings [data-key]')) {
        const key = el.dataset.key;
        if (!key) continue;
        const f = HELD.get(el);
        if (el.dataset.env === '1') {
          const envKey = el.value.trim();
          if (!envKey) {
            // No key typed. An inline credential the record already holds is written back as it
            // was, unseen (resolved from HELD_MARK below); deleting a working credential because the
            // form will not show it would be its own outage. Removed on request.
            if (heldSecret(f) !== undefined) settings[key] = HELD_MARK;
            continue;
          }
          const ref = { env: envKey };
          if (el.dataset.cast) ref.cast = el.dataset.cast;
          if (HELD_DEFAULTS.has(key)) ref.default = HELD_MARK;
          else if (f.envDefault !== undefined) ref.default = f.envDefault;
          settings[key] = ref;
          continue;
        }
        if (el.dataset.kind === 'checkbox') {
          // A checkbox has no "untouched" state, so one the record did not set, left at the schema
          // default, writes nothing: the rule coerce in connectionForm.ts applies. Without it every
          // edit save wrote an explicit value for each default bool.
          const dflt = f.defaultValue;
          if (f.value === undefined && dflt !== undefined && dflt !== null && el.checked === dflt) continue;
          settings[key] = el.checked;
          continue;
        }
        if (f.value != null && el.value === SHOWN.get(el)) {
          settings[key] = f.value;            // untouched: the recorded value, exactly
          continue;
        }
        const raw = el.value.trim();
        if (raw === '') continue;             // emptied -> omit the key entirely
        settings[key] = typedValue(f, raw);
      }
      for (const row of document.querySelectorAll('#settings .setting')) {
        const inputs = row.querySelectorAll('input[type=text]');
        const key = inputs[0].value.trim();
        if (!key) continue;
        const raw = inputs[1].value.trim();
        const envCb = row.querySelector('input[type=checkbox]');
        const castSel = row.querySelector('select');
        const was = ROW_ORIGINAL.get(row);
        if (was && was.key === inputs[0].value && inputs[1].value === was.shown &&
            envCb.checked === was.isEnv && castSel.value === was.cast) {
          settings[key] = was.original;       // untouched: the recorded value, exactly
          continue;
        }
        if (envCb.checked) {
          const ref = { env: raw };
          if (castSel.value) ref.cast = castSel.value;
          if (was && isEnvRefValue(was.original) && was.original.default !== undefined) ref.default = was.original.default;
          settings[key] = ref;
        } else {
          settings[key] = inputs[1].dataset.table === '1' ? parseTable(raw) : coerce(raw);
        }
      }
      return forHost ? settings : resolveHeld(settings);
    }

    // Swap HELD_MARK back for the held value on save. A clone gets neither the inline credential nor
    // a secret env reference's inline default: the GUI must not be what writes a new inline credential
    // into the file (FieldDescriptor.secretOnlyEnv). A removed credential is written as nothing.
    function resolveHeld(settings) {
      for (const key of Object.keys(settings)) {
        const value = settings[key];
        if (value === HELD_MARK) {
          const secret = HELD_SECRETS.get(key);
          if (secret === undefined || CLONE || REMOVED_SECRETS.has(key)) delete settings[key];
          else settings[key] = secret;
        } else if (value !== null && typeof value === 'object' && value.default === HELD_MARK) {
          // A copy: the value may be a descriptor's own recorded object.
          const ref = { ...value };
          const dflt = HELD_DEFAULTS.get(key);
          if (dflt === undefined || CLONE) delete ref.default;
          else ref.default = dflt;
          settings[key] = ref;
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
    // this page. Both post "error", and both answer the page's "fields" request. A field is a
    // FieldDescriptor from connectionForm.ts: its declared fields with their types. The two
    // unknown-typed values (value, defaultValue, envDefault, preserveValue) are not typed there
    // either, and their presence is not checked: all four are optional there, and FieldDescriptor
    // says why value and defaultValue can be absent, so a presence check would discard ordinary
    // "fields" messages. This page reads envDefault and preserveValue only to write them back on
    // save (HELD), and never shows either. choices is
    // required and may be null; envKey, cast and a group's description may be absent and are never
    // null.
    // control and type are closed sets: the lists FieldControl and ParamType are derived from.
    const FIELD_CONTROLS = ${embedJson(FIELD_CONTROLS)};
    const PARAM_TYPES = ${embedJson(PARAM_TYPES)};
    function mfFieldDescriptor(f) {
      return mfObj(f) && mfStr(f.key) && mfStr(f.label) && mfOneOf(f.control, FIELD_CONTROLS) &&
        mfOneOf(f.type, PARAM_TYPES) &&
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
