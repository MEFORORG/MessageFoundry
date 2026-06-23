// Alert-rule editor (ADR 0014) — a webview that manages the operator alert rules in the service-
// settings TOML's `[[alerts.rules]]` by shelling the `messagefoundry alert list|add|remove` CLI
// (which validates + writes comment-preservingly). Rules are pure routing/threshold DATA — there is
// no embedded code — so, like connections.toml (ADR 0007), they are GUI-manageable.
//
// Rules are an ordered, first-match-wins list, so this is a list manager (author a new rule → it is
// appended; remove by row) rather than the one-record-by-name form the connection editor is. Editing
// a rule is remove + re-add. A change lands in the file immediately but the engine reads `[alerts]`
// at startup, so it takes effect on the next engine restart (not via Promote/reload) — the UI says so.
import * as vscode from "vscode";
import { runJson, serviceConfig, workspaceDir } from "./cli";

const EVENT_TYPES = [
  "any",
  "connection_stopped",
  "queue_buildup",
  "storage_threshold",
  "cert_expiry",
];
const SEVERITIES = ["info", "warning", "critical"];

// One rule as the CLI emits it from `alert list` (the AlertRule fields + the read-only ordinal).
interface Rule {
  index: number;
  event_type?: string;
  connection?: string;
  min_depth?: number | null;
  min_oldest_seconds?: number | null;
  severity?: string;
  transports?: string[] | null;
  cooldown_seconds?: number | null;
}

// A rule to create — the AlertRule fields only (no index). transports: omitted = all configured;
// [] = suppress; a subset routes to just those transports.
type NewRule = Omit<Rule, "index">;

let panel: vscode.WebviewPanel | undefined;

/** Open the alert-rule editor: lists the current `[[alerts.rules]]` and lets the user append/remove. */
export async function openAlertEditor(context: vscode.ExtensionContext): Promise<void> {
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
    "messagefoundry.alertEditor",
    "Alert Rules",
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

  current.webview.onDidReceiveMessage(async (m: { command?: string; rule?: NewRule; index?: number }) => {
    if (m?.command === "add" && m.rule) {
      await add(m.rule, current);
    } else if (m?.command === "remove" && typeof m.index === "number") {
      await remove(m.index, current);
    } else if (m?.command === "cancel") {
      current.dispose();
    }
  });

  current.webview.html = formHtml(current.webview);
  await refresh(current);
}

/** Re-read `alert list` and push the rows to the webview (after open and after every mutation). */
async function refresh(current: vscode.WebviewPanel): Promise<void> {
  const ws = workspaceDir();
  if (!ws) {
    return;
  }
  try {
    const rules = await runJson<Rule[]>(["alert", "list", "--service-config", serviceConfig()], ws);
    current.webview.postMessage({ command: "rules", rules });
  } catch (e) {
    current.webview.postMessage({ command: "error", message: String(e) });
  }
}

async function add(rule: NewRule, current: vscode.WebviewPanel): Promise<void> {
  const ws = workspaceDir();
  if (!ws) {
    return;
  }
  try {
    await runJson(
      ["alert", "add", "--service-config", serviceConfig(), "--data", JSON.stringify(rule)],
      ws,
    );
  } catch (e) {
    // Surface the validation error inline so the user can fix the form (file was not changed).
    current.webview.postMessage({ command: "error", message: String(e) });
    return;
  }
  await refresh(current);
  void vscode.window.showInformationMessage(
    "MessageFoundry: added alert rule. Restart the engine to apply (rules load at startup).",
  );
}

async function remove(index: number, current: vscode.WebviewPanel): Promise<void> {
  const ws = workspaceDir();
  if (!ws) {
    return;
  }
  const confirm = await vscode.window.showWarningMessage(
    `Remove alert rule #${index}?`,
    { modal: true },
    "Remove",
  );
  if (confirm !== "Remove") {
    return;
  }
  try {
    await runJson(
      ["alert", "remove", "--service-config", serviceConfig(), "--index", String(index)],
      ws,
    );
  } catch (e) {
    current.webview.postMessage({ command: "error", message: String(e) });
    return;
  }
  await refresh(current);
}

function nonce(): string {
  let s = "";
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  for (let i = 0; i < 24; i++) {
    s += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return s;
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
    body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); padding: 12px 16px; max-width: 760px; }
    h2 { font-size: 15px; margin: 0 0 4px; }
    .sub { font-size: 11px; color: var(--vscode-descriptionForeground); margin: 0 0 14px; }
    label { display: block; font-size: 12px; color: var(--vscode-descriptionForeground); margin: 10px 0 2px; }
    input, select { width: 100%; box-sizing: border-box; padding: 5px 8px; font-family: inherit; font-size: 13px;
      color: var(--vscode-input-foreground); background: var(--vscode-input-background);
      border: 1px solid var(--vscode-input-border, var(--vscode-panel-border)); border-radius: 2px; }
    .row { display: flex; gap: 12px; }
    .row > div { flex: 1; }
    .hint { font-size: 11px; color: var(--vscode-descriptionForeground); margin-top: 4px; }
    .actions { margin-top: 16px; display: flex; gap: 8px; }
    button { font-family: inherit; color: var(--vscode-button-foreground); background: var(--vscode-button-background);
      border: none; padding: 6px 14px; cursor: pointer; border-radius: 2px; }
    button.secondary { color: var(--vscode-button-secondaryForeground); background: var(--vscode-button-secondaryBackground); }
    button:hover { background: var(--vscode-button-hoverBackground); }
    .error { display: none; margin-top: 12px; font-size: 12px; color: var(--vscode-errorForeground); white-space: pre-wrap; }
    hr { border: none; border-top: 1px solid var(--vscode-panel-border); margin: 18px 0; }
    table { width: 100%; border-collapse: collapse; font-size: 12px; margin-top: 6px; }
    th, td { text-align: left; padding: 4px 8px; border-bottom: 1px solid var(--vscode-panel-border); }
    th { color: var(--vscode-descriptionForeground); font-weight: 600; }
    td.idx { color: var(--vscode-descriptionForeground); }
    .empty { font-size: 12px; color: var(--vscode-descriptionForeground); margin-top: 6px; }
    button.rm { padding: 2px 8px; background: transparent; color: var(--vscode-errorForeground); }
  </style>
</head>
<body>
  <h2>Alert Rules</h2>
  <p class="sub">Operator rules over the alert notifier (ADR 0014), stored in <code>[[alerts.rules]]</code> of the
     service-settings TOML. <b>First match wins.</b> Rules are pure data (no code). A change takes effect on the
     next engine <b>restart</b> — the engine reads <code>[alerts]</code> at startup.</p>

  <h2 style="font-size:13px;">Current rules</h2>
  <table id="rules"><thead><tr>
    <th>#</th><th>Event</th><th>Connection</th><th>Depth≥</th><th>Age≥(s)</th><th>Severity</th><th>Transports</th><th>Cooldown(s)</th><th></th>
  </tr></thead><tbody id="rows"></tbody></table>
  <div id="empty" class="empty">No rules yet — an event matching no rule notifies every configured transport at <code>warning</code>.</div>

  <hr />

  <h2 style="font-size:13px;">New rule</h2>
  <div class="row">
    <div><label for="event_type">Event type</label><select id="event_type"></select></div>
    <div><label for="connection">Connection (glob)</label><input id="connection" value="*" /></div>
  </div>
  <div class="row">
    <div><label for="min_depth">Min depth</label><input id="min_depth" type="number" min="1" placeholder="(any)" />
      <div class="hint">queue_buildup only — match at/over this lane depth.</div></div>
    <div><label for="min_oldest_seconds">Min oldest (s)</label><input id="min_oldest_seconds" type="number" min="0" placeholder="(any)" />
      <div class="hint">queue_buildup only — …or oldest-in-lane age.</div></div>
  </div>
  <div class="row">
    <div><label for="severity">Severity</label><select id="severity"></select></div>
    <div><label for="cooldown_seconds">Cooldown (s)</label><input id="cooldown_seconds" type="number" min="0.001" placeholder="(global re-alert)" />
      <div class="hint">Re-alert interval for matching events; blank = global default.</div></div>
  </div>
  <label for="transports">Transports</label>
  <select id="transports">
    <option value="all">All configured transports (default)</option>
    <option value="webhook">Webhook only</option>
    <option value="email">Email only</option>
    <option value="both">Webhook + email</option>
    <option value="suppress">Suppress (notify nothing)</option>
  </select>
  <div class="hint">Route matching events to specific transports, or suppress them entirely.</div>

  <div id="error" class="error"></div>

  <div class="actions">
    <button id="add">Add rule</button>
    <button id="close" class="secondary">Close</button>
  </div>

  <script nonce="${n}">
    const vscode = acquireVsCodeApi();
    const EVENT_TYPES = ${embed(EVENT_TYPES)};
    const SEVERITIES = ${embed(SEVERITIES)};
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

    window.addEventListener('message', (e) => {
      const d = e.data || {};
      if (d.command === 'rules') { renderRules(d.rules || []); errorEl.style.display = 'none'; }
      else if (d.command === 'error') { show(d.message); }
    });
  </script>
</body>
</html>`;
}
