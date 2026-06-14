// Connection editor (ADR 0007) — a webview form that creates/edits a connection in the workspace's
// connections.toml by shelling the `messagefoundry connection upsert|remove` CLI (which validates +
// writes comment-preservingly). Logic (routers/handlers) stays in .py; this edits transport config.
// A connection authored in .py is read-only here (it isn't in `connection list`) — the gear opens its
// source instead. After a save the graph refreshes and a Promote is offered.
import * as vscode from "vscode";
import { configDir, runJson, workspaceDir } from "./cli";

const TRANSPORTS = ["mllp", "tcp", "file", "rest", "database", "database_poll", "soap", "sftp", "ftp"];

interface ConnObj {
  direction: "inbound" | "outbound";
  name: string;
  transport: string;
  router?: string;
  settings?: Record<string, unknown>;
  ack_mode?: string;
  strict?: boolean;
  ordering?: string;
  retry?: Record<string, unknown>;
  [k: string]: unknown;
}

let panel: vscode.WebviewPanel | undefined;

export interface EditorOpts {
  routers: string[];
  editName?: string; // edit an existing (TOML-authored) connection; omit to create
  onSaved?: () => void;
}

/** Open the connection editor. In edit mode, pre-fills from `connection list`; if the name isn't a
 *  data-authored connection (it's in a .py module), informs the user and bails (the gear opens its
 *  source instead). */
export async function openConnectionEditor(
  context: vscode.ExtensionContext,
  opts: EditorOpts,
): Promise<void> {
  const ws = workspaceDir();
  if (!ws) {
    void vscode.window.showInformationMessage("MessageFoundry: open a workspace folder first.");
    return;
  }

  let initial: ConnObj | undefined;
  if (opts.editName) {
    let entries: ConnObj[];
    try {
      entries = await runJson<ConnObj[]>(["connection", "list", "--config", configDir()], ws);
    } catch (e) {
      void vscode.window.showErrorMessage(`MessageFoundry: could not read connections — ${String(e)}`);
      return;
    }
    initial = entries.find((c) => c.name === opts.editName);
    if (!initial) {
      void vscode.window.showInformationMessage(
        `MessageFoundry: ${opts.editName} is authored in code (a .py module), not connections.toml — ` +
          "edit its source. The GUI manages connections.toml connections.",
      );
      return;
    }
  }

  if (panel) {
    panel.dispose(); // reopen fresh for the new target
  }
  panel = vscode.window.createWebviewPanel(
    "messagefoundry.connectionEditor",
    initial ? `Edit ${initial.name}` : "New Connection",
    vscode.ViewColumn.Active,
    { enableScripts: true },
  );
  const current = panel;
  current.onDidDispose(() => {
    if (panel === current) {
      panel = undefined;
    }
  }, null, context.subscriptions);

  current.webview.onDidReceiveMessage(async (m: { command?: string; conn?: ConnObj; name?: string }) => {
    if (m?.command === "save" && m.conn) {
      await save(m.conn, current, opts.onSaved);
    } else if (m?.command === "delete" && m.name) {
      await remove(m.name, current, opts.onSaved);
    } else if (m?.command === "cancel") {
      current.dispose();
    }
  });

  current.webview.html = formHtml(current.webview, opts.routers, initial);
}

async function save(conn: ConnObj, current: vscode.WebviewPanel, onSaved?: () => void): Promise<void> {
  const ws = workspaceDir();
  if (!ws) {
    return;
  }
  try {
    await runJson(["connection", "upsert", "--config", configDir(), "--data", JSON.stringify(conn)], ws);
  } catch (e) {
    // Surface the validation/egress error inline so the user can fix the form (file was not changed).
    current.webview.postMessage({ command: "error", message: String(e) });
    return;
  }
  current.dispose();
  onSaved?.();
  const pick = await vscode.window.showInformationMessage(
    `MessageFoundry: saved ${conn.name} to connections.toml.`,
    "Promote…",
  );
  if (pick === "Promote…") {
    void vscode.commands.executeCommand("messagefoundry.promote");
  }
}

async function remove(name: string, current: vscode.WebviewPanel, onSaved?: () => void): Promise<void> {
  const ws = workspaceDir();
  if (!ws) {
    return;
  }
  const confirm = await vscode.window.showWarningMessage(
    `Remove connection "${name}" from connections.toml?`,
    { modal: true },
    "Remove",
  );
  if (confirm !== "Remove") {
    return;
  }
  try {
    await runJson(["connection", "remove", "--config", configDir(), "--name", name], ws);
  } catch (e) {
    current.webview.postMessage({ command: "error", message: String(e) });
    return;
  }
  current.dispose();
  onSaved?.();
  void vscode.window.showInformationMessage(`MessageFoundry: removed ${name} from connections.toml.`);
}

function nonce(): string {
  let s = "";
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  for (let i = 0; i < 24; i++) {
    s += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return s;
}

// Embed a value as JSON safe to drop inside a <script> (escape < so a "</script>" in data can't break out).
function embed(value: unknown): string {
  return JSON.stringify(value ?? null).replace(/</g, "\\u003c");
}

function formHtml(webview: vscode.Webview, routers: string[], initial?: ConnObj): string {
  const n = nonce();
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta http-equiv="Content-Security-Policy"
        content="default-src 'none'; style-src ${webview.cspSource} 'unsafe-inline'; script-src 'nonce-${n}';" />
  <style>
    body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); padding: 12px 16px; max-width: 680px; }
    h2 { font-size: 15px; margin: 0 0 4px; }
    .sub { font-size: 11px; color: var(--vscode-descriptionForeground); margin: 0 0 12px; }
    label { display: block; font-size: 12px; color: var(--vscode-descriptionForeground); margin: 10px 0 2px; }
    input, select { width: 100%; box-sizing: border-box; padding: 5px 8px; font-family: inherit; font-size: 13px;
      color: var(--vscode-input-foreground); background: var(--vscode-input-background);
      border: 1px solid var(--vscode-input-border, var(--vscode-panel-border)); border-radius: 2px; }
    .row { display: flex; gap: 12px; }
    .row > div { flex: 1; }
    .name { font-family: var(--vscode-editor-font-family, monospace); }
    .actions { margin-top: 18px; display: flex; gap: 8px; }
    button { font-family: inherit; color: var(--vscode-button-foreground); background: var(--vscode-button-background);
      border: none; padding: 6px 14px; cursor: pointer; border-radius: 2px; }
    button.secondary { color: var(--vscode-button-secondaryForeground); background: var(--vscode-button-secondaryBackground); }
    button.danger { background: transparent; color: var(--vscode-errorForeground); margin-left: auto; }
    button:hover { background: var(--vscode-button-hoverBackground); }
    .hint { font-size: 11px; color: var(--vscode-descriptionForeground); margin-top: 4px; }
    .check { display: block; margin-top: 12px; font-size: 13px; }
    .check input { width: auto; margin-right: 6px; vertical-align: middle; }
    .setting { display: flex; gap: 8px; align-items: center; margin-top: 6px; }
    .setting input[type=text] { flex: 1; }
    .setting .k { flex: 0 0 32%; }
    .setting select { flex: 0 0 80px; }
    .setting .envbox { flex: 0 0 auto; font-size: 12px; color: var(--vscode-descriptionForeground); white-space: nowrap; }
    .setting .envbox input { width: auto; margin-right: 4px; vertical-align: middle; }
    .setting button { padding: 4px 8px; }
    .error { display: none; margin-top: 12px; font-size: 12px; color: var(--vscode-errorForeground); white-space: pre-wrap; }
  </style>
</head>
<body>
  <h2 id="title">New Connection</h2>
  <p class="sub">Edits <code>connections.toml</code> — transport config as data. Routers/handlers stay in .py.
     Secrets/peers use an env() reference, never inline.</p>

  <div class="row">
    <div><label for="direction">Direction</label>
      <select id="direction">
        <option value="inbound">Inbound (receives)</option>
        <option value="outbound">Outbound (sends)</option>
      </select>
    </div>
    <div><label for="transport">Transport</label>
      <select id="transport"></select>
    </div>
  </div>

  <label for="name">Connection name</label>
  <input id="name" class="name" placeholder="IB_ACME_ADT" />

  <div id="router-row"><label for="router">Router</label>
    <select id="router"></select>
    <div class="hint">The inbound feeds this router (defined in a .py module).</div>
  </div>

  <label>Settings</label>
  <div class="hint">Per-transport keys (e.g. MLLP inbound: <code>port</code>; outbound: <code>host</code>, <code>port</code>).
     Tick <b>env()</b> to reference an environment value instead of a literal.</div>
  <div id="settings"></div>
  <button id="addSetting" class="secondary" style="margin-top:8px;">+ setting</button>

  <div id="inbound-opts">
    <div class="row">
      <div><label for="ackMode">ACK mode</label>
        <select id="ackMode">
          <option value="">original (default)</option>
          <option value="enhanced">enhanced</option>
          <option value="none">none</option>
        </select>
      </div>
      <div><label class="check" style="margin-top:28px;"><input type="checkbox" id="strict" /> Strict validation</label></div>
    </div>
  </div>

  <div id="outbound-opts">
    <div class="row">
      <div><label for="ordering">Ordering</label>
        <select id="ordering">
          <option value="">FIFO (default)</option>
          <option value="fifo">fifo</option>
          <option value="unordered">unordered</option>
        </select>
      </div>
      <div><label for="maxAttempts">Retry max attempts (blank = forever)</label><input id="maxAttempts" /></div>
    </div>
  </div>

  <div id="error" class="error"></div>

  <div class="actions">
    <button id="save">Save</button>
    <button id="cancel" class="secondary">Cancel</button>
    <button id="delete" class="danger" style="display:none;">Remove…</button>
  </div>

  <script nonce="${n}">
    const vscode = acquireVsCodeApi();
    const INITIAL = ${embed(initial)};
    const ROUTERS = ${embed(routers)};
    const TRANSPORTS = ${embed(TRANSPORTS)};
    const EDIT = INITIAL !== null;
    const $ = (id) => document.getElementById(id);
    const errorEl = $('error');

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

    const HINTS = {
      'mllp:inbound': ['port'], 'mllp:outbound': ['host', 'port'],
      'tcp:inbound': ['port'], 'tcp:outbound': ['host', 'port'],
      'file:inbound': ['directory', 'pattern'], 'file:outbound': ['directory', 'filename'],
    };
    function prefillHints() {
      if (EDIT) return;
      $('settings').innerHTML = '';
      const keys = HINTS[$('transport').value + ':' + $('direction').value] || [];
      if (keys.length) { for (const k of keys) settingRow(k, '', false, ''); }
      else settingRow('', '', false, '');
    }

    function refreshVisibility() {
      $('router-row').style.display = isInbound() ? '' : 'none';
      $('inbound-opts').style.display = isInbound() ? '' : 'none';
      $('outbound-opts').style.display = isInbound() ? 'none' : '';
    }

    // ----- load initial (edit) or defaults (create) -----
    if (EDIT) {
      $('title').textContent = 'Edit ' + INITIAL.name;
      $('direction').value = INITIAL.direction; $('direction').disabled = true;
      $('name').value = INITIAL.name; $('name').disabled = true;  // rename = remove + create
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
      $('delete').style.display = '';
    } else {
      prefillHints();
    }
    refreshVisibility();

    $('direction').addEventListener('change', () => { refreshVisibility(); prefillHints(); });
    $('transport').addEventListener('change', prefillHints);
    $('addSetting').addEventListener('click', () => settingRow('', '', false, ''));

    function coerce(text) {
      if (text === 'true') return true;
      if (text === 'false') return false;
      if (/^-?\\d+$/.test(text)) return parseInt(text, 10);
      if (/^-?\\d*\\.\\d+$/.test(text)) return parseFloat(text);
      return text;
    }

    function build() {
      const direction = $('direction').value;
      const conn = { direction: direction, name: $('name').value.trim(), transport: $('transport').value };
      const settings = {};
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
      if (Object.keys(settings).length) conn.settings = settings;
      if (direction === 'inbound') {
        if ($('router').value) conn.router = $('router').value;
        if ($('ackMode').value) conn.ack_mode = $('ackMode').value;
        if ($('strict').checked) conn.strict = true;
      } else {
        if ($('ordering').value) conn.ordering = $('ordering').value;
        const ma = $('maxAttempts').value.trim();
        if (ma) conn.retry = { max_attempts: parseInt(ma, 10) };
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

    window.addEventListener('message', (e) => {
      if (e.data && e.data.command === 'error') { errorEl.textContent = e.data.message; errorEl.style.display = ''; }
    });
  </script>
</body>
</html>`;
}
