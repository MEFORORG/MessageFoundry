// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
//
// The connection editor webview's inline script, split out of connectionEditor.ts so it can be
// loaded without `vscode`. connectionEditor.ts builds the page and embeds this; the unit suite
// evaluates the SAME source in a jsdom page (webview-receivers.test.ts), so what the tests exercise
// is what ships.
import {
  ENVREF_KEY_NAMES,
  FIELD_CONTROLS,
  NON_FINITE_SPELLINGS,
  NON_FINITE_TAG,
  PARAM_TYPES,
} from "./connectionForm";
import {
  CHANNEL_FIELD,
  SHAPE_HELPERS,
  WEBVIEW_GUARD_NOTE,
  SCRIPT_STARTED_MARK,
  embedJson,
  guardScript,
} from "./webviewMessaging";

/** What the connection editor's script is seeded with, each embedded as JSON. */
export interface ConnectionEditorScriptInputs {
  initial: unknown;
  routers: readonly string[];
  transports: readonly string[];
  fieldGroups: unknown;
  /** The transport and direction `fieldGroups` was built for; null when there are none. */
  fieldGroupsFor: { transport: string; direction: string } | null;
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
    // The transport and direction the host built FIELD_GROUPS for, so create mode can show them.
    const FIELD_GROUPS_FOR = ${embedJson(p.fieldGroupsFor)};
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

    // A non-finite float arrives as the tag {"$toml": "inf"} (isNonFiniteTag in connectionForm.ts,
    // whose names are embedded here). It is a leaf: shown as its spelling, passed through untouched.
    const NON_FINITE_TAG = ${embedJson(NON_FINITE_TAG)};
    const NON_FINITE_SPELLINGS = ${embedJson(NON_FINITE_SPELLINGS)};
    function isNonFiniteTag(val) {
      if (!val || typeof val !== 'object' || Array.isArray(val)) return false;
      const keys = Object.keys(val);
      return keys.length === 1 && keys[0] === NON_FINITE_TAG && NON_FINITE_SPELLINGS.includes(val[NON_FINITE_TAG]);
    }

    // A value as a text input shows it: a table or array as JSON, never String(value), which shows
    // and saves '[object Object]' (BACKLOG #5565).
    function displayValue(value) {
      if (isNonFiniteTag(value)) return value[NON_FINITE_TAG];
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
      // A non-finite tag is a number, not a table: it shows its spelling and is marked so an edited
      // inf / -inf posts the tag again.
      if (isNonFiniteTag(value)) v.dataset.nonfinite = '1';
      else if (value !== null && typeof value === 'object') v.dataset.table = '1';
      const castSel = document.createElement('select');
      // A recorded cast outside the list gets its own option, so it shows and an untouched save keeps
      // it for the engine to refuse, rather than the select going blank and the save dropping it.
      const casts = ['', 'int', 'float', 'bool', 'str'];
      if (cast && !casts.includes(cast)) casts.push(cast);
      for (const c of casts) { const o = document.createElement('option'); o.value = c; o.textContent = c || 'cast'; castSel.appendChild(o); }
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
    // Text boxes the user has typed into. An env key box whose recorded key holds a line break
    // shows it without, so it judges "untouched" by this as well as by SHOWN: retyping what the box
    // shows is the user's repair and saves the typed key, while leaving it saves the recorded key.
    const TYPED = new WeakSet();
    // The record's inline credentials (HELD_SECRETS) and secret env references' inline defaults
    // (HELD_DEFAULTS), by key. A transport or direction change sends the host HELD_MARK in their
    // place, never the value: the host rebuilds the fields from what it is sent, so the key (and an
    // off-direction secret's field) survives the round trip, and a key the new schema does not
    // declare comes back showing the mark rather than the credential. The save swaps the value back.
    const HELD_MARK = '[held inline credential, not shown]';
    const HELD_SECRETS = new Map();
    // Each entry is { value, envKey }: the default and the env key it was recorded under, as an
    // untouched box shows it (line breaks stripped) and trimmed. The default goes back only with
    // that key, however many rebuilds came between.
    const HELD_DEFAULTS = new Map();
    // Keys whose inline credential the user chose to remove; the save then writes no value for them.
    const REMOVED_SECRETS = new Set();
    function heldSecret(f) {
      if (REMOVED_SECRETS.has(f.key)) return undefined;
      if (f.preserveValue !== undefined && f.preserveValue !== HELD_MARK) return f.preserveValue;
      // Only where the rebuild was sent the mark: a key the request left out, because the user
      // removed or cleared it, holds nothing, so the credential is not written back.
      return f.preserveValue === HELD_MARK ? HELD_SECRETS.get(f.key) : undefined;
    }
    // Keys the user chose to remove from the record; the save writes nothing for them. Cleared when
    // the fields are rebuilt, since the rebuild request already left them out.
    const REMOVED_KEYS = new Set();
    // The keys the record itself carries (none on a create). A rebuild's descriptors cannot say
    // this: they carry whatever the rebuild request sent as the value.
    const RECORDED_KEYS = new Set(Object.keys((INITIAL && INITIAL.settings) || {}));
    // The cast an env() reference needs to read back as the field's declared type.
    const ENV_CASTS = { int: 'int', float: 'float', bool: 'bool' };
    // The descriptor a field gets when the user switches it between a literal and env(): empty, so
    // the save writes nothing until a value or a key is typed.
    function switchedMode(f, toEnv) {
      const g = { ...f, isEnvRef: toEnv, value: undefined, envKey: undefined, envDefault: undefined, cast: undefined };
      if (toEnv && ENV_CASTS[f.type]) g.cast = ENV_CASTS[f.type];
      return g;
    }
    // recorded: the descriptor the record drew, kept across a switch so switching back restores it.
    // replacing: the field's current element, when a switch redraws it in place.
    function renderField(f, into, replacing, recorded) {
      const drawn = recorded || f;
      const wrap = document.createElement('div'); wrap.className = 'field';
      const lab = document.createElement('label');
      lab.textContent = f.label + (f.required ? ' *' : f.conditionallyRequired ? ' †' : '');
      lab.title = f.help || '';
      if (f.preserveValue !== undefined && f.preserveValue !== HELD_MARK) HELD_SECRETS.set(f.key, f.preserveValue);
      if (f.secret && f.envDefault !== undefined && f.envDefault !== HELD_MARK) {
        HELD_DEFAULTS.set(f.key, { value: f.envDefault, envKey: String(f.envKey ?? '').replace(/[\\r\\n]/g, '').trim() });
      }
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
        // save keeps it, rather than the select going blank and the save dropping the key. A table
        // matches a table choice by content, whatever its key order; a scalar by its text.
        const recordedChoice = f.value == null ? undefined : choices.find((c) =>
          c !== null && typeof c === 'object' ? canon(c) === canon(f.value) : displayValue(c) === displayValue(f.value));
        if (f.value != null && recordedChoice === undefined) options.push(f.value);
        for (const c of options) {
          const o = document.createElement('option');
          o.value = displayValue(c); o.textContent = c === '' ? '(default: ' + f.placeholder + ')' : displayValue(c);
          control.appendChild(o);
        }
        control.value = displayValue(recordedChoice !== undefined ? recordedChoice : f.value);
      } else {
        control = document.createElement('input');
        // Never a number box, only a numeric keyboard hint: a number box reads text it cannot parse
        // as "", so a typo was saved as an emptied box and the recorded key was dropped. A text box
        // posts what was typed; typedValue converts a number and the engine refuses anything else.
        control.type = 'text';
        if (f.control === 'number' && !useEnv) control.setAttribute('inputmode', 'decimal');
        control.placeholder = useEnv ? secretHint(f) : (f.placeholder || '');
        control.value = displayValue(useEnv ? (f.envKey || '') : f.value);
        control.addEventListener('input', () => TYPED.add(control));
      }
      control.dataset.key = f.key;
      control.dataset.kind = f.control === 'checkbox' && !boolish ? 'text' : f.control;
      if (useEnv) { control.dataset.env = '1'; }
      if (f.cast) { control.dataset.cast = f.cast; }
      HELD.set(control, f);
      SHOWN.set(control, control.value);
      control.disabled = REMOVED_KEYS.has(f.key);
      const hint = document.createElement('div'); hint.className = 'sub'; hint.textContent = f.help || '';
      wrap.append(lab, control);
      // Switch between a literal and env(), as the legacy row's env() box did. Not for a secret: the
      // form must not be what writes a literal credential into the file (secretOnlyEnv).
      if (f.envAllowed && !f.secret && !f.secretOnlyEnv) {
        const envLabel = document.createElement('label'); envLabel.className = 'envbox';
        const envCb = document.createElement('input'); envCb.type = 'checkbox'; envCb.checked = useEnv;
        envCb.dataset.envToggle = f.key;
        envLabel.append(envCb, document.createTextNode('env()'));
        envCb.addEventListener('change', () => {
          const next = envCb.checked === !!drawn.isEnvRef ? drawn : switchedMode(drawn, envCb.checked);
          renderField(next, into, wrap, drawn);
        });
        wrap.append(envLabel);
      }
      // Remove a setting the record holds, as the legacy row's delete did. A checkbox has no empty
      // state, so without this a recorded bool could only be set, never dropped to the default.
      if (drawn.isEnvRef || drawn.value != null) {
        const drop = document.createElement('button'); drop.className = 'secondary';
        drop.dataset.removeKey = f.key;
        const label = () => { drop.textContent = REMOVED_KEYS.has(f.key) ? 'Keep this setting' : 'Remove this setting'; };
        label();
        drop.addEventListener('click', () => {
          if (REMOVED_KEYS.has(f.key)) REMOVED_KEYS.delete(f.key); else REMOVED_KEYS.add(f.key);
          label();
          control.disabled = REMOVED_KEYS.has(f.key);
        });
        wrap.append(drop);
      }
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
      if (replacing) into.replaceChild(wrap, replacing); else into.appendChild(wrap);
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
      REMOVED_KEYS.clear();
      // A held default survives a draw from the host (the load, or a rebuild's reply) only where
      // that draw gives its key an env reference: otherwise the request it answers sent none,
      // because the setting was removed, emptied or switched to a literal. Dropped here, when the
      // reply is drawn, not when the request is sent, so a setting kept again before the reply
      // arrives keeps its default (BACKLOG #8243 items 18 and 20). A reference under another key
      // keeps it, so the original key typed back still finds it.
      // A rebuild's reply is drawn only when it answers the page's latest request, matched by the
      // id the host echoes (the message handler), so a reply to an older request never reaches
      // this prune (item 18).
      const envRefKeys = new Set();
      for (const g of groups) for (const f of g.fields) if (f.envKey !== undefined || f.envDefault !== undefined) envRefKeys.add(f.key);
      for (const k of HELD_DEFAULTS.keys()) if (!envRefKeys.has(k)) HELD_DEFAULTS.delete(k);
      for (const g of groups) {
        const box = document.createElement('details'); box.open = !g.collapsed;
        const sum = document.createElement('summary');
        sum.textContent = g.title + ' (' + g.fields.length + ')';
        if (g.description) { sum.title = g.description; }
        box.appendChild(sum);
        for (const f of g.fields) { renderField(f, box); }
        host.appendChild(box);
      }
      // Fields that draw nothing, at load in any mode or in a rebuild's reply: the free-text row,
      // a working form, rather than an empty settings area.
      if (!host.querySelector('[data-key]')) settingRow('', '', false, '');
    }

    /** Legacy path: no schema fields to draw, so the free-text key/value rows. Rows already drawn,
     *  and what was typed into them, stay; a blank row is drawn only where there is none. */
    function prefillHints() {
      if (EDIT) return;
      if ($('settings').querySelector('.setting')) return;
      $('settings').innerHTML = '';
      settingRow('', '', false, '');
    }

    // Each fields request carries an id, one more than the last (FIELDS_SEQ). Both hosts echo it
    // in their reply (fieldsReply in connectionEditor.ts), with the transport and direction the
    // groups were built for. The page draws only the reply to its latest request, so a reply to an
    // older one can neither drop nor bring back a setting (BACKLOG #8243 items 18 and 20).
    // FIELDS_ANSWERED is the id of the latest request answered. While the two differ, the drawn
    // fields were built for another transport or direction than the pickers show, so Save waits
    // (fieldsPending). ASKED_SETTINGS is what the latest request sent, as JSON.
    let FIELDS_SEQ = 0;
    let FIELDS_ANSWERED = 0;
    let ASKED_SETTINGS = null;
    // The transport and direction the drawn fields were built for, set once the load has drawn,
    // so a request the host could not answer puts the pickers back where the fields are.
    let DRAWN_FOR = null;
    function fieldsPending() { return FIELDS_SEQ !== FIELDS_ANSWERED; }

    /** Ask the extension to rebuild the descriptors when the transport or direction changes.
     *  settings: what collectSettings(true) returns, when the caller already has it. */
    function requestFields(settings) {
      if (!FIELD_GROUPS) { prefillHints(); return; }
      // A setting this request leaves out (removed, or its env key box empty) loses its held default
      // when the reply is drawn (renderGroups), not here.
      if (settings === undefined) settings = collectSettings(true);
      FIELDS_SEQ += 1;
      ASKED_SETTINGS = JSON.stringify(settings);
      // The request names this page's render, so the host can drop a reply that would reach a
      // newer page: the token current when the host handles it may already be that page's.
      vscode.postMessage({
        command: 'fields',
        seq: FIELDS_SEQ,
        transport: $('transport').value,
        direction: $('direction').value,
        settings: settings,
        ${CHANNEL_FIELD}: MF_CHANNEL,
      });
    }

    // A value as text that does not depend on key order, so a recorded table matches a table
    // choice by content (renderField).
    function canon(v) {
      if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
      if (v !== null && typeof v === 'object') {
        return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
      }
      return JSON.stringify(v);
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
    } else if (FIELD_GROUPS && FIELD_GROUPS_FOR && TRANSPORTS.includes(FIELD_GROUPS_FOR.transport) &&
        [...$('direction').options].some((o) => o.value === FIELD_GROUPS_FOR.direction)) {
      // Create: the pickers show the transport and direction the host built the fields for, so the
      // two agree from the first draw and the host's default (MLLP) stays the default.
      $('transport').value = FIELD_GROUPS_FOR.transport;
      $('direction').value = FIELD_GROUPS_FOR.direction;
      renderGroups(FIELD_GROUPS);
    } else {
      // Create with no schema, or with fields built for a transport or direction the pickers
      // cannot show: the free-text row, a working form that names no
      // transport's fields. With a schema, a transport or direction change still asks for that
      // transport's fields, carrying what was typed.
      prefillHints();
    }
    refreshVisibility();
    DRAWN_FOR = { transport: $('transport').value, direction: $('direction').value };

    $('direction').addEventListener('change', () => { refreshVisibility(); requestFields(); });
    $('transport').addEventListener('change', () => requestFields());
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

    // Edited text for a schema field, read by the field's declared type: a select takes the matching
    // choice with its JSON type, even where the record held a table; any other table, or value the
    // record held as a table, parses as JSON; a bool is converted when the text is one; a number only when the text is a finite decimal,
    // which is narrower than coerce in connectionForm.ts, since a text box here takes any text; anything else, and text that does not convert, is posted verbatim, so the
    // engine's validator refuses what the user typed rather than this page guessing.
    const DECIMAL_TEXT = /^-?(\\d+(\\.\\d+)?|\\.\\d+)([eE][-+]?\\d+)?$/;
    function typedValue(f, raw) {
      // A select takes the picked choice itself, with its own type, matched by the text its option
      // was written with (displayValue): a select whose recorded value was a table must not
      // JSON-parse a choice such as "2" into a number, and a table choice is posted as the table,
      // whatever the other choices are (BACKLOG #8243 item 31). Text no choice matches falls through.
      if (f.control === 'select') {
        const hit = (f.choices || []).find((c) => displayValue(c) === raw);
        if (hit !== undefined) return hit;
      }
      // TOML's inf / -inf typed into a float field is carried as the tag the engine decodes; "nan"
      // is posted as typed, for the engine to refuse.
      if (f.type === 'float' && (raw === 'inf' || raw === '-inf')) return { [NON_FINITE_TAG]: raw };
      const tableValued = f.value !== null && typeof f.value === 'object' && !isNonFiniteTag(f.value);
      if (f.control === 'table' || tableValued) return parseTable(raw);
      if (f.control === 'select') return raw;
      // Only decimal text, the text a number box accepted: Number() also reads hex, binary, octal
      // and a leading '+', which would post a number the user never typed. An exponent that
      // overflows is posted as typed too, since Infinity would cross to the host as null, and so is
      // an int past the range a JS number holds exactly, which would round to another integer.
      if (f.type === 'int' || f.type === 'float') {
        const n = DECIMAL_TEXT.test(raw) ? Number(raw) : NaN;
        if (!Number.isFinite(n)) return raw;
        return f.type === 'int' && Number.isInteger(n) && !Number.isSafeInteger(n) ? raw : n;
      }
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
        if (!key || REMOVED_KEYS.has(key)) continue;
        const f = HELD.get(el);
        if (el.dataset.env === '1') {
          const envKey = el.value.trim();
          // An untouched box writes back the recorded key exactly, surrounding spaces, line breaks
          // and a key of only spaces included: the engine looks the key up as written, so a trimmed
          // key names another variable (BACKLOG #8243 item 19). A key the user typed is trimmed.
          // A box that shows the recorded key is untouched while it still shows it, typed in or
          // not; one that shows it without its line breaks is untouched only until typed in, which
          // is how such a key is repaired (TYPED).
          const shownKey = SHOWN.get(el);
          const untouchedKey = f.envKey !== undefined && el.value === shownKey &&
            (shownKey === f.envKey || !TYPED.has(el));
          if (!envKey && !untouchedKey) {
            // No key typed. An inline credential the record already holds is written back as it
            // was, unseen (resolved from HELD_MARK below); deleting a working credential because the
            // form will not show it would be its own outage. Removed on request.
            if (heldSecret(f) !== undefined) settings[key] = HELD_MARK;
            continue;
          }
          const ref = { env: untouchedKey ? f.envKey : envKey };
          if (el.dataset.cast) ref.cast = el.dataset.cast;
          // A held inline default goes back only with the env key it was recorded under, compared
          // trimmed, so an untouched key and the original key typed back after a rebuild keep it,
          // and a replaced key does not take the old credential as its default. A setting the user
          // removed loses its held default when the rebuild is drawn (renderGroups).
          // A secret's default is never written from the descriptor: only as the mark, so resolveHeld
          // decides it and a clone never copies it.
          const held = HELD_DEFAULTS.get(key);
          if (held !== undefined) {
            if (envKey === held.envKey) ref.default = HELD_MARK;
          } else if (f.envDefault !== undefined && !f.secret) {
            ref.default = f.envDefault;
          }
          settings[key] = ref;
          continue;
        }
        if (el.dataset.kind === 'checkbox') {
          // A checkbox has no "untouched" state, so one the record did not set, left at the schema
          // default, writes nothing: the rule coerce in connectionForm.ts documents. Without it every
          // edit save wrote an explicit value for each default bool. "The record set it" is judged
          // against the record itself, not the descriptor: a transport or direction rebuild carries
          // what was ticked as the field's value, so a box moved off its default and back before
          // the rebuild would otherwise write the default (BACKLOG #5976).
          // A box with no schema default is drawn unticked for "never set", so for this rule its unset
          // position is unticked: an unticked box the record did not set posts nothing rather than
          // false. Ticked and unticked again looks the same as never touched, and posts the same.
          // A REQUIRED one is the exception: omitting it is a missing setting the engine refuses, so
          // it always posts what it shows.
          const dflt = f.defaultValue === undefined || f.defaultValue === null ? false : f.defaultValue;
          const fromRecord = f.value !== undefined && RECORDED_KEYS.has(key);
          if (!fromRecord && !f.required && el.checked === dflt) continue;
          settings[key] = el.checked;
          continue;
        }
        if (f.value != null && el.value === SHOWN.get(el)) {
          settings[key] = f.value;            // untouched: the recorded value, exactly
          continue;
        }
        // A select's value is the picked option's, written from the choice itself, so it is not
        // trimmed: a choice with surrounding spaces must still match (typedValue).
        const raw = el.tagName === 'SELECT' ? el.value : el.value.trim();
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
          const nonFinite = inputs[1].dataset.nonfinite === '1' && (raw === 'inf' || raw === '-inf');
          settings[key] = nonFinite ? { [NON_FINITE_TAG]: raw }
            : inputs[1].dataset.table === '1' ? parseTable(raw) : coerce(raw);
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
          const held = HELD_DEFAULTS.get(key);
          if (held === undefined || CLONE) delete ref.default;
          else ref.default = held.value;
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
      // The drawn fields belong to the transport and direction of the last answered request; until
      // the latest one is answered, saving would post those fields under the pickers' transport.
      if (fieldsPending()) {
        errorEl.textContent = 'The fields for the ' + $('transport').value + ' transport are still loading; save once they show.';
        errorEl.style.display = '';
        return;
      }
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
    // A "fields" reply echoes its request's id (seq) and the transport and direction its groups were
    // built for (fieldsReply in connectionEditor.ts). An "error" answering a fields request the host
    // could not rebuild carries that request's id too; other errors carry none.
    const DIRECTIONS = ['inbound', 'outbound'];
    const SHAPES = {
      error: (d) => mfStr(d.message) && mfOpt(d.seq, mfInt),
      fields: (d) => mfInt(d.seq) && mfStr(d.transport) && mfOneOf(d.direction, DIRECTIONS) &&
        mfArrOf(d.groups, (g) => mfObj(g) && mfStr(g.title) && mfBool(g.collapsed) &&
        mfOpt(g.description, mfStr) && mfArrOf(g.fields, mfFieldDescriptor)),
    };
    ${WEBVIEW_GUARD_NOTE}
    window.addEventListener('message', (e) => {
      const d = mfTrusted(e);
      if (!d || !mfShapeOk(d, 'command', SHAPES, 'connection editor')) { return; }
      if (d.command === 'error') {
        let message = d.message;
        if (d.seq !== undefined) {
          // A newer request is still waiting for its answer: this one's failure no longer matters.
          if (d.seq !== FIELDS_SEQ) return;
          // The latest request could not be answered, so no reply will come: the pickers go back
          // to the transport and direction the drawn fields belong to, and Save works again.
          FIELDS_ANSWERED = FIELDS_SEQ;
          $('transport').value = DRAWN_FOR.transport;
          $('direction').value = DRAWN_FOR.direction;
          refreshVisibility();
          message += '. The form shows the ' + DRAWN_FOR.transport + ' ' + DRAWN_FOR.direction + ' fields again.';
        }
        errorEl.textContent = message; errorEl.style.display = '';
      }
      // Rebuilt descriptors after a transport/direction change. The grouping rules stay in the tested
      // module; the webview only draws what it is handed.
      if (d.command === 'fields') {
        // Only the reply to the latest request is drawn: a reply to an older one would drop or
        // change a setting the latest request carries, or bring back one it left out.
        if (d.seq !== FIELDS_SEQ) return;
        // The form changed since the latest request (a setting removed, kept again, emptied,
        // retyped or switched between a literal and env()): drawing its reply would undo that, so
        // ask again with the form as it is now (BACKLOG #8243 items 18 and 20). Each reply sends at
        // most one request, and the form does not change until a reply is drawn, so this stops once
        // the user stops editing. Save waits meanwhile (fieldsPending).
        if (ASKED_SETTINGS !== null) {
          const now = collectSettings(true);
          if (JSON.stringify(now) !== ASKED_SETTINGS) { requestFields(now); return; }
        }
        FIELDS_ANSWERED = d.seq;
        DRAWN_FOR = { transport: d.transport, direction: d.direction };
        FIELD_GROUPS = d.groups;
        renderGroups(FIELD_GROUPS);
      }
    });
  `;
}
