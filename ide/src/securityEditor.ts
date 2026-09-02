// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Organization and contributors
// [security] posture editor (ADR 0118) — a webview form that manages the plain-language, secure-by-
// default switches in the service-settings TOML's `[security]` section by shelling the
// `messagefoundry security show|set` CLI (which validates + writes comment-preservingly, and REJECTS the
// relocated legacy keys). This is the SOLE authoring surface for `[security]`; the web console is
// read-only (GET /security/posture). The switches are pure data (booleans/ints/strings, no code), so —
// like connections.toml (ADR 0007) and [[alerts.rules]] (ADR 0014) — they are GUI-manageable.
//
// Every switch defaults to the SECURE position; when the operator moves one to its insecure value the
// form shows a plain-language loosening warning in place (CISA "make deviations from safe defaults
// obvious"). A change takes effect on the next engine restart (the TOML is read at startup).
import * as vscode from "vscode";
import { runJson, serviceConfig, workspaceDir } from "./cli";
import { nonce } from "./cspNonce";

type FieldType = "bool" | "int" | "string" | "tristate";

interface Field {
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
const FIELDS: Field[] = [
  // ── Network access ──────────────────────────────────────────────
  { key: "local_access_only", label: "Local access only", type: "bool", group: "Network access",
    desc: "Reach the operator API + web console only from this machine (loopback bind).",
    insecure: false, risk: "the operator API/console is reachable off this machine" },
  { key: "listen_address", label: "Listen address", type: "string", group: "Network access",
    desc: "Bind address — used only when local access only is off." },
  { key: "require_encryption_for_remote", label: "Require encryption for remote", type: "bool", group: "Network access",
    desc: "Any off-machine access must be over TLS.",
    insecure: false, risk: "off-machine access is permitted WITHOUT TLS (still refused on a production-PHI bind)" },
  { key: "serve_web_console", label: "Serve web console", type: "bool", group: "Network access",
    desc: "Mount the browser ops console at /ui — ON by default (ADR 0143; the console is the operator UI). Set it off to shrink to a JSON-only surface. Default-on applies to local loopback binds; off-box it needs TLS + a public address." },
  { key: "web_console_public_address", label: "Web console public address", type: "string", group: "Network access",
    desc: "External origin when the console is exposed off-box (e.g. https://ops.example.com)." },
  // ── Encryption of stored data ───────────────────────────────────
  { key: "encrypt_stored_data", label: "Encrypt stored data", type: "bool", group: "Encryption",
    desc: "PHI is encrypted at rest (key from the environment).",
    insecure: false, risk: "at-rest encryption is off (a PHI instance still refuses unless keyless PHI is allowed)" },
  { key: "allow_unencrypted_phi", label: "Allow unencrypted PHI", type: "bool", group: "Encryption",
    desc: "Audited escape: start a PHI instance with NO encryption key.",
    insecure: true, risk: "a PHI instance may start keyless — PHI stored UNENCRYPTED at rest" },
  { key: "allow_unencrypted_phi_under_strict_enforcement", label: "Allow unencrypted PHI under strict enforcement", type: "bool", group: "Encryption",
    desc: "Second audited ack (with 'Allow unencrypted PHI') REQUIRED to start a PHI instance keyless under strict enforcement (ADR 0140).",
    insecure: true, risk: "a PHI instance may start keyless under strict enforcement — PHI stored UNENCRYPTED at rest" },
  // ── Sign-in & identity ──────────────────────────────────────────
  { key: "require_sign_in", label: "Require sign-in", type: "bool", group: "Sign-in & identity",
    desc: "Authenticate every request.",
    insecure: false, risk: "authentication is DISABLED (loopback-only; a non-loopback bind refuses)" },
  { key: "require_mfa", label: "Require MFA", type: "bool", group: "Sign-in & identity",
    desc: "Second factor (native TOTP) for admin step-up.",
    insecure: false, risk: "the Administrator role is single-factor — no TOTP second factor" },
  { key: "allow_single_factor_admin_when_exposed", label: "Allow single-factor admin when exposed", type: "bool", group: "Sign-in & identity",
    desc: "Audited ack (ADR 0140): permit single-factor admin on an EXPOSED production-PHI bind — lifts the production refusal to a warning.",
    insecure: true, risk: "single-factor admin is permitted on an EXPOSED production-PHI bind — no second factor over the network" },
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
  { key: "audit_all_authorization_decisions", label: "Audit all authorization decisions", type: "bool", group: "Data handling",
    desc: "PHI access is ALWAYS audited; this records the grant for every authorization decision on top. On by default (BACKLOG #1277).",
    insecure: false, risk: "every authenticated READ is authorized but NOT recorded — what an account reached cannot be reconstructed afterwards" },
  // ── What this instance handles ──────────────────────────────────
  { key: "handles_real_patient_data", label: "Handles real patient data", type: "tristate", group: "What this instance handles",
    desc: "The master posture lever. Derived from the environment name when unset (dev → no, staging/prod → yes)." },
  { key: "production_instance", label: "Production instance", type: "tristate", group: "What this instance handles",
    desc: "Production-tier posture. Derived from the environment name when unset." },
];

interface ShowResult {
  values: Record<string, unknown>;
  set: string[];
  defaults: Record<string, unknown>;
  loosenings: { switch: string; risk: string }[];
}

let panel: vscode.WebviewPanel | undefined;

/** Open the [security] editor: loads the current switches + secure defaults and saves edits via the CLI. */
export async function openSecurityEditor(context: vscode.ExtensionContext): Promise<void> {
  const ws = workspaceDir();
  if (!ws) {
    void vscode.window.showInformationMessage("MessageFoundry: open a workspace folder first.");
    return;
  }
  if (panel) {
    panel.reveal(vscode.ViewColumn.Active);
    void refresh(panel);
    return;
  }
  panel = vscode.window.createWebviewPanel(
    "messagefoundry.securityEditor",
    "Security Settings",
    vscode.ViewColumn.Active,
    { enableScripts: true },
  );
  const current = panel;
  current.onDidDispose(
    () => {
      if (panel === current) {
        panel = undefined;
      }
    },
    null,
    context.subscriptions,
  );
  current.webview.onDidReceiveMessage(
    async (m: { command?: string; updates?: Record<string, unknown> }) => {
      if (m?.command === "save" && m.updates) {
        await save(m.updates, current);
      } else if (m?.command === "cancel") {
        current.dispose();
      }
    },
  );
  current.webview.html = formHtml(current.webview);
  await refresh(current);
}

/** Re-read `security show` and push the current state (values + defaults + loosenings) to the webview. */
async function refresh(current: vscode.WebviewPanel): Promise<void> {
  const ws = workspaceDir();
  if (!ws) {
    return;
  }
  try {
    const state = await runJson<ShowResult>(
      ["security", "show", "--service-config", serviceConfig()],
      ws,
    );
    current.webview.postMessage({ command: "state", state });
  } catch (e) {
    current.webview.postMessage({ command: "error", message: String(e) });
  }
}

/** Save the edited switches: `updates` maps each key to its value, or null to reset it to the secure
 *  default (the CLI drops the key). Validation errors surface inline; the file is only touched on success. */
async function save(
  updates: Record<string, unknown>,
  current: vscode.WebviewPanel,
): Promise<void> {
  const ws = workspaceDir();
  if (!ws) {
    return;
  }
  try {
    await runJson(
      ["security", "set", "--service-config", serviceConfig(), "--data", JSON.stringify(updates)],
      ws,
    );
  } catch (e) {
    current.webview.postMessage({ command: "error", message: String(e) });
    return;
  }
  await refresh(current);
  void vscode.window.showInformationMessage(
    "MessageFoundry: saved [security] settings. Restart the engine to apply (read at startup).",
  );
}

function embed(value: unknown): string {
  return JSON.stringify(value ?? null).replace(/</g, "\\u003c");
}

function formHtml(webview: vscode.Webview): string {
  const n = nonce();
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta http-equiv="Content-Security-Policy"
        content="default-src 'none'; style-src ${webview.cspSource} 'unsafe-inline'; script-src 'nonce-${n}';" />
  <style>
    body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); padding: 12px 16px; max-width: 780px; }
    h2 { font-size: 15px; margin: 0 0 4px; }
    h3 { font-size: 12px; text-transform: uppercase; letter-spacing: .04em; color: var(--vscode-descriptionForeground); margin: 20px 0 6px; }
    .sub { font-size: 11px; color: var(--vscode-descriptionForeground); margin: 0 0 8px; }
    .field { margin: 10px 0; }
    .field label { font-size: 13px; }
    .field .desc { font-size: 11px; color: var(--vscode-descriptionForeground); margin-top: 2px; }
    .field.loosened { border-left: 2px solid var(--vscode-inputValidation-warningBorder, #cca700); padding-left: 8px; margin-left: -10px; }
    .warn { display: none; font-size: 11px; color: var(--vscode-inputValidation-warningForeground, var(--vscode-editorWarning-foreground)); margin-top: 3px; }
    .field.loosened .warn { display: block; }
    input[type=text], input[type=number], select { box-sizing: border-box; padding: 4px 8px; font-family: inherit; font-size: 13px;
      color: var(--vscode-input-foreground); background: var(--vscode-input-background);
      border: 1px solid var(--vscode-input-border, var(--vscode-panel-border)); border-radius: 2px; min-width: 220px; }
    .row { display: flex; align-items: baseline; gap: 10px; }
    .row .ctl { min-width: 240px; }
    .actions { margin-top: 20px; display: flex; gap: 8px; }
    button { font-family: inherit; color: var(--vscode-button-foreground); background: var(--vscode-button-background);
      border: none; padding: 6px 14px; cursor: pointer; border-radius: 2px; }
    button.secondary { color: var(--vscode-button-secondaryForeground); background: var(--vscode-button-secondaryBackground); }
    button:hover { background: var(--vscode-button-hoverBackground); }
    .error { display: none; margin-top: 12px; font-size: 12px; color: var(--vscode-errorForeground); white-space: pre-wrap; }
    code { font-family: var(--vscode-editor-font-family); }
  </style>
</head>
<body>
  <h2>Security settings</h2>
  <p class="sub">The <code>[security]</code> posture in the service-settings TOML (ADR 0118). Every switch
     defaults to the <b>secure</b> position; loosening one is warned in place. Saved changes apply on the next
     engine <b>restart</b>. Editing is IDE-only — the web console shows this posture read-only.</p>
  <div id="form"></div>
  <div id="error" class="error"></div>
  <div class="actions">
    <button id="save">Save</button>
    <button id="close" class="secondary">Close</button>
  </div>

  <script nonce="${n}">
    const vscode = acquireVsCodeApi();
    const FIELDS = ${embed(FIELDS)};
    const $ = (id) => document.getElementById(id);
    const errorEl = $('error');
    let defaults = {};

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
      errorEl.style.display = 'none';
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

    function show(msg) { errorEl.textContent = msg; errorEl.style.display = ''; }

    $('save').addEventListener('click', () => vscode.postMessage({ command: 'save', updates: collectUpdates() }));
    $('close').addEventListener('click', () => vscode.postMessage({ command: 'cancel' }));

    // Origin is NOT checked here — see webviewMessaging.ts.
    window.addEventListener('message', (e) => {
      const d = e.data || {};
      if (d.command === 'state') { render(d.state || {}); }
      else if (d.command === 'error') { show(d.message); }
    });

    buildForm();
  </script>
</body>
</html>`;
}
