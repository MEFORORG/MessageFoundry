// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
//
// The Security Settings webview's inline script, split out of securityEditor.ts so it can be loaded
// without `vscode`. securityEditor.ts builds the page and embeds this; the unit suite evaluates the
// SAME source in a jsdom page (webview-receivers.test.ts), so what the tests exercise is what
// ships.
import { SHAPE_HELPERS, WEBVIEW_GUARD_NOTE, embedJson, guardScript } from "./webviewMessaging";

// The switches live here rather than in securityEditor.ts so the unit suite renders the real list.
export type FieldType = "bool" | "int" | "string" | "tristate";

export interface Field {
  key: string;
  label: string;
  desc: string;
  type: FieldType;
  group: string;
  // The value that is a LOOSENING (mirrors security_loosenings in config/settings.py); undefined = the
  // switch is never a loosening on its own (listen_address, the posture lever, session lifetimes).
  insecure?: boolean | number;
  risk?: string;
}

// The switches, grouped, with friendly labels + plain-language descriptions. Kept in step with
// SecuritySettings (config/settings.py) + security_loosenings().
export const FIELDS: Field[] = [
  // ── Network access ──────────────────────────────────────────────
  { key: "local_access_only", label: "Local access only", type: "bool", group: "Network access",
    desc: "Reach the operator API + web console only from this machine (loopback bind).",
    insecure: false, risk: "the operator API/console is reachable off this machine" },
  { key: "listen_address", label: "Listen address", type: "string", group: "Network access",
    desc: "Bind address — used only when local access only is off." },
  { key: "require_encryption_for_remote", label: "Require encryption for remote", type: "bool", group: "Network access",
    desc: "Any off-machine access must be over TLS.",
    insecure: false, risk: "off-machine access is permitted with no operator certificate: the API serves on its self-signed placeholder and inbound listeners without tls bind in cleartext (still refused under enforcement=enforce)" },
  { key: "serve_web_console", label: "Serve web console", type: "bool", group: "Network access",
    desc: "Mount the browser ops console at /ui — ON by default (ADR 0143; the console is the operator UI). Set it off to shrink to a JSON-only surface. Default-on applies to local loopback binds; off-box it needs TLS + a public address." },
  { key: "web_console_public_address", label: "Web console public address", type: "string", group: "Network access",
    desc: "External origin when the console is exposed off-box (e.g. https://ops.example.com)." },
  // ── Encryption of stored data ───────────────────────────────────
  { key: "encrypt_stored_data", label: "Encrypt stored data", type: "bool", group: "Encryption",
    desc: "PHI is encrypted at rest (key from the environment). Off sets the same keyless-PHI opt-out as allow_unencrypted_phi; a configured key still encrypts.",
    insecure: false, risk: "a PHI instance may start keyless — PHI stored UNENCRYPTED at rest (the same opt-out as allow_unencrypted_phi)" },
  { key: "allow_unencrypted_phi", label: "Allow unencrypted PHI", type: "bool", group: "Encryption",
    desc: "Audited escape: start a PHI instance with NO encryption key.",
    insecure: true, risk: "a PHI instance may start keyless — PHI stored UNENCRYPTED at rest" },
  { key: "allow_unencrypted_phi_under_strict_enforcement", label: "Allow unencrypted PHI under strict enforcement", type: "bool", group: "Encryption",
    desc: "Second audited ack (with 'Allow unencrypted PHI') REQUIRED to start a PHI instance keyless under strict enforcement (ADR 0140).",
    insecure: true, risk: "a PHI instance may start keyless under strict enforcement — PHI stored UNENCRYPTED at rest" },
  // ── Sign-in & identity ──────────────────────────────────────────
  { key: "require_mfa", label: "Require MFA", type: "bool", group: "Sign-in & identity",
    desc: "Require an engine second factor at sign-in, from every account by default; a covered local account enrols TOTP before it adds a passkey. An OIDC sign-in meets it with an amr/acr claim checked while [auth].oidc_require_mfa_claim is on; require_mfa_scope can free a local account without the Administrator role.",
    insecure: false, risk: "an account with no second factor enrolled is single-factor, so a Kerberos session enters on a ticket that asserts no strength. An enrolled account owes its factor only while it keeps one, and its holder may remove the last. Where an OIDC sign-in carries an amr/acr claim checked while [auth].oidc_require_mfa_claim is on, that claim counts as the second factor, whether or not one is enrolled" },
  { key: "allow_single_factor_admin_when_exposed", label: "Allow single-factor sign-in when exposed", type: "bool", group: "Sign-in & identity",
    desc: "Audited ack (ADR 0140): lifts the start refusal that an exposed instance with Require MFA off meets under strict enforcement.",
    insecure: true, risk: "an EXPOSED instance under enforcement = enforce may start with [security].require_mfa off, on an audited warning instead of the refusal. Every account with no second factor enrolled is then single-factor over the network, unless an OIDC sign-in carries an amr/acr claim checked while [auth].oidc_require_mfa_claim is on" },
  { key: "sign_out_after_idle_minutes", label: "Sign out after idle (min)", type: "int", group: "Sign-in & identity",
    desc: "Session idle timeout, in minutes." },
  { key: "max_session_hours", label: "Max session (hours)", type: "int", group: "Sign-in & identity",
    desc: "Absolute session lifetime, in hours." },
  // ── Data handling ───────────────────────────────────────────────
  { key: "block_unlisted_outbound", label: "Block unlisted outbound", type: "bool", group: "Data handling",
    desc: "Deny-by-default egress — only allow-listed destinations send.",
    insecure: false, risk: "outbound egress is allow-any — a transform may send PHI to any destination" },
  { key: "delete_message_bodies_after_days", label: "Delete message bodies after (days)", type: "int", group: "Data handling",
    desc: "Bounded PHI-body retention; 0 = keep indefinitely (audited).",
    insecure: 0, risk: "message bodies are kept indefinitely (a PHI instance still auto-bounds/refuses per posture)" },
  { key: "allow_keeping_phi_indefinitely", label: "Allow keeping PHI indefinitely", type: "bool", group: "Data handling",
    desc: "Audited escape: unbounded PHI retention.",
    insecure: true, risk: "unbounded PHI retention is permitted" },
  // The per-tier retention acknowledgements (BACKLOG #1967, #2280). 'Allow keeping PHI indefinitely'
  // above covers the auto-bounded tiers only and does NOT satisfy these. Each `risk` mirrors
  // security_loosenings(); tests/test_security_config.py reds when a risk drifts, when a tier's
  // switch is missing here, or when one is not a bool whose `true` is the loosening.
  { key: "allow_keeping_transform_state_indefinitely", label: "Allow keeping transform state indefinitely", type: "bool", group: "Data handling",
    desc: "Audited acknowledgement: [retention].state_max_age_days may stay unset. Under strict enforcement the engine refuses to start without this or a window. Read [retention] in docs/CONFIGURATION.md before choosing a window on this tier.",
    insecure: true, risk: "the PL-2 tier [retention].state_max_age_days may start with no retention window and accumulate without bound" },
  { key: "allow_keeping_search_presets_indefinitely", label: "Allow keeping search presets indefinitely", type: "bool", group: "Data handling",
    desc: "Audited acknowledgement: [retention].search_preset_days may stay unset. Under strict enforcement the engine refuses to start without this or a window.",
    insecure: true, risk: "the PL-2 tier [retention].search_preset_days may start with no retention window and accumulate without bound" },
  { key: "allow_keeping_app_logs_indefinitely", label: "Allow keeping app logs indefinitely", type: "bool", group: "Data handling",
    desc: "Audited acknowledgement: [retention].app_log_days may stay unset while [logging].log_dir is set. Under strict enforcement the engine refuses to start without this or a window.",
    insecure: true, risk: "the PL-1 tier [retention].app_log_days may start with no retention window and accumulate without bound" },
  { key: "allow_keeping_backup_archives_indefinitely", label: "Allow keeping backup archives indefinitely", type: "bool", group: "Data handling",
    desc: "Audited acknowledgement: [backup].retention_keep may be 0 while [backup].destination is set. Under strict enforcement the engine refuses to start without this or a keep count.",
    insecure: true, risk: "the PL-1 tier [backup].retention_keep may start with no retention window and accumulate without bound" },
  { key: "audit_all_authorization_decisions", label: "Audit all authorization decisions", type: "bool", group: "Data handling",
    desc: "PHI access is ALWAYS audited; this records the grant for every authorization decision on top. On by default (BACKLOG #1277).",
    insecure: false, risk: "every authenticated READ is authorized but NOT recorded — what an account reached cannot be reconstructed afterwards" },
  // ── What this instance handles ──────────────────────────────────
  // `handles_real_patient_data` sat here and is retired (BACKLOG #1279): every instance carries
  // patient data, so there is no declaration to edit. The engine REFUSES the key at load, so leaving
  // a row here would offer an edit that breaks the config it writes.
  { key: "production_instance", label: "Production instance", type: "tristate", group: "What this instance handles",
    desc: "Production-tier posture. Derived from the environment name when unset." },
];

/** The whole inline `<script>` body for one render, guard included. `token` is this render's
 *  channel token, minted by the caller with the nonce (webviewMessaging.ts). */
export function securityEditorScript(token: string, fields: unknown): string {
  return `
    const vscode = acquireVsCodeApi();${guardScript(token)}${SHAPE_HELPERS}
    const FIELDS = ${embedJson(fields)};
    const $ = (id) => document.getElementById(id);
    const errorEl = $('error');
    let defaults = {};
    // The refusal now showing, or '' while the form is up. See refuse().
    let refusal = '';

    // Build the grouped form once; values are filled in on 'state'.
    function buildForm() {
      const root = $('form');
      root.innerHTML = '';
      let group = null;
      for (const f of FIELDS) {
        if (f.group !== group) { group = f.group; const h = document.createElement('h3'); h.textContent = group; root.appendChild(h); }
        const wrap = document.createElement('div'); wrap.className = 'field'; wrap.id = 'field-' + f.key;
        const row = document.createElement('div'); row.className = 'row';
        const label = document.createElement('label'); label.textContent = f.label; label.setAttribute('for', 'in-' + f.key);
        const ctl = document.createElement('span'); ctl.className = 'ctl';
        let input;
        if (f.type === 'bool') {
          input = document.createElement('select');
          for (const [v, t] of [['true','Yes'],['false','No']]) { const o = document.createElement('option'); o.value = v; o.textContent = t; input.appendChild(o); }
        } else if (f.type === 'tristate') {
          input = document.createElement('select');
          for (const [v, t] of [['','Derived from environment'],['true','Yes'],['false','No']]) { const o = document.createElement('option'); o.value = v; o.textContent = t; input.appendChild(o); }
        } else if (f.type === 'int') {
          input = document.createElement('input'); input.type = 'number'; input.min = '0';
        } else {
          input = document.createElement('input'); input.type = 'text';
        }
        input.id = 'in-' + f.key;
        input.addEventListener('change', () => markLoosened(f, input));
        input.addEventListener('input', () => markLoosened(f, input));
        ctl.appendChild(input);
        row.appendChild(label); row.appendChild(ctl); wrap.appendChild(row);
        const desc = document.createElement('div'); desc.className = 'desc'; desc.textContent = f.desc; wrap.appendChild(desc);
        if (f.risk !== undefined) { const w = document.createElement('div'); w.className = 'warn'; w.textContent = 'Loosened: ' + f.risk + '.'; wrap.appendChild(w); }
        root.appendChild(wrap);
      }
    }

    function currentValue(f) {
      const input = $('in-' + f.key);
      if (f.type === 'bool') return input.value === 'true';
      if (f.type === 'tristate') return input.value === '' ? null : input.value === 'true';
      if (f.type === 'int') { const v = input.value.trim(); return v === '' ? 0 : Number(v); }
      return input.value;
    }

    function markLoosened(f, input) {
      if (f.insecure === undefined) return;
      const v = currentValue(f);
      const loosened = (v === f.insecure);
      $('field-' + f.key).classList.toggle('loosened', loosened);
    }

    function setValue(f, value) {
      const input = $('in-' + f.key);
      if (f.type === 'tristate') { input.value = value === null || value === undefined ? '' : String(value); }
      else if (f.type === 'bool') { input.value = String(value === true); }
      else if (f.type === 'int') { input.value = value == null ? '' : String(value); }
      else { input.value = value == null ? '' : String(value); }
      markLoosened(f, input);
    }

    function render(state) {
      defaults = state.defaults || {};
      for (const f of FIELDS) { setValue(f, state.values ? state.values[f.key] : undefined); }
      refusal = '';
      errorEl.style.display = 'none';
      $('form').style.display = '';
      $('save').disabled = false;
    }

    // A state this form cannot read. The form is hidden and Save goes off, so nothing can be written
    // from placeholders or from the values of an earlier state. textContent (through show): the
    // problem names a switch, and no part of a message is ever parsed as markup here.
    function refuse(problem) {
      $('save').disabled = true;
      $('form').style.display = 'none';
      refusal = 'These settings cannot be shown. The state sent to this form is malformed: ' + problem +
        '. Save is off until a well-formed state arrives.';
      show(refusal);
    }

    function collectUpdates() {
      // Send only values that differ from the secure default; a value AT the default is sent as null so
      // the CLI removes the key (keeps the file lean). Nulls are removals; non-nulls are explicit sets.
      const updates = {};
      for (const f of FIELDS) {
        const v = currentValue(f);
        const d = defaults[f.key];
        const same = (v === d) || (v === null && (d === null || d === undefined));
        updates[f.key] = same ? null : v;
      }
      return updates;
    }

    // 'block', not '': the page's stylesheet hides .error, and clearing the inline value would hand
    // the element back to that rule, so the text would be set and never seen.
    function show(msg) { errorEl.textContent = msg; errorEl.style.display = 'block'; }

    $('save').addEventListener('click', () => vscode.postMessage({ command: 'save', updates: collectUpdates() }));
    $('close').addEventListener('click', () => vscode.postMessage({ command: 'cancel' }));

    // The JS type each FIELDS type arrives as, and how the refusal names it. Types only: a negative
    // int is a value range, which is a different requirement (webviewMessaging.ts, SHAPE_HELPERS).
    // mfInt is Number.isSafeInteger, so a fraction and a number past 2^53 are refused as not an int.
    // null is a value only for a tristate: elsewhere it would render as "No" or as an empty number.
    const TYPE_OK = {
      bool: { ok: mfBool, want: 'true or false' },
      int: { ok: mfInt, want: 'a whole number' },
      string: { ok: mfStr, want: 'text' },
      tristate: { ok: (x) => x === null || mfBool(x), want: 'true, false or null' },
    };

    // What is wrong with the first switch in o (state.values or state.defaults) that is missing or
    // has the wrong type, or null when every FIELDS switch is there with its type.
    // EVERY switch is required in BOTH objects. "security show" prints the whole settings model
    // twice (the file's values, then the defaults), so a missing switch is a malformed state. It is
    // refused for the reason a null is: setValue() would show an absent Yes/No as "No" and an absent
    // number as empty, and Save would write that as false or 0. A tristate that is unset arrives as
    // null, which is present. Keys with no FIELDS entry are never read, so never checked.
    function switchProblem(o, where) {
      for (const f of FIELDS) {
        const name = where + '.' + f.key;
        const v = o[f.key];
        if (v === undefined) { return name + ' is missing'; }
        // Own-property lookup, so a FIELDS type with no entry here fails closed and does not throw.
        const t = Object.prototype.hasOwnProperty.call(TYPE_OK, f.type) ? TYPE_OK[f.type] : null;
        if (!t) { return name + ' has a type this form does not know'; }
        if (t.ok(v) !== true) { return name + ' must be ' + t.want + ', got ' + mfKind(v); }
      }
      return null;
    }

    // What is wrong with a 'state' message, or null. The state is ShowResult, the JSON "security
    // show" prints. All four of its fields are required: the two objects the form renders from, with
    // every switch, and the two it does not read (set, loosenings), which the command always prints.
    function stateProblem(d) {
      const s = d.state;
      if (!mfObj(s)) { return 'state is missing or is not an object'; }
      for (const where of ['values', 'defaults']) {
        if (!mfObj(s[where])) { return where + ' is missing or is not an object'; }
        const problem = switchProblem(s[where], where);
        if (problem !== null) { return problem; }
      }
      if (!mfArrOf(s.set, mfStr)) { return 'set is missing or is not a list of text'; }
      if (!mfArrOf(s.loosenings, (l) => mfObj(l) && mfStr(l.switch) && mfStr(l.risk))) {
        return 'loosenings is missing or is not a list of switch and risk entries';
      }
      return null;
    }

    // One entry per message the host posts (at least securityEditor.ts).
    const SHAPES = {
      state: (d) => stateProblem(d) === null,
      error: (d) => mfStr(d.message),
    };
    ${WEBVIEW_GUARD_NOTE}
    window.addEventListener('message', (e) => {
      const d = mfTrusted(e);
      if (!d) { return; }
      if (!mfShapeOk(d, 'command', SHAPES, 'Security Settings')) {
        // A discarded state is shown as well as warned: an empty form with no reason reads as broken.
        // The fallback text covers a discard stateProblem() does not explain, so "null" is never shown.
        if (d.command === 'state') { refuse(stateProblem(d) || 'it is malformed'); }
        return;
      }
      if (d.command === 'state') { render(d.state); }
      // After a refusal the form is still hidden, so the reason stays up beside the new error.
      else if (d.command === 'error') { show(refusal ? refusal + ' The engine also reported: ' + d.message : d.message); }
    });

    // Save stays off until a state has rendered. Until then the form holds placeholders, not the file's
    // values (every Yes/No shows its first option), and saving those would write them as explicit sets.
    $('save').disabled = true;
    buildForm();
  `;
}
