// "New Connection" — a webview form: pick a type, fill the key fields, and it generates a config
// module (<configDir>/<name>.py) with the inbound()/outbound() declaration. The name is auto-built
// from the [TYPE]_[PARTNER]_[MESSAGE] convention. Only built transports (MLLP/File) are creatable;
// SFTP/SOAP/REST/DB appear disabled until implemented.
import * as path from "node:path";
import * as vscode from "vscode";
import { configDir, workspaceDir } from "./cli";

type Kind = "mllp-in" | "mllp-out" | "file-in" | "file-out";

interface CreatePayload {
  kind: Kind;
  name: string;
  partner?: string; // convention input (also validated server-side)
  message?: string; // convention input (also validated server-side)
  host?: string;
  port?: string;
  router?: string;
  directory?: string;
  pattern?: string;
  filename?: string;
  ackMode?: string; // mllp-in: original | enhanced | none
  strict?: boolean; // mllp-in
  hl7Version?: string; // mllp-in
  scaffold?: boolean; // inbound: also generate the router + a handler stub
}

let panel: vscode.WebviewPanel | undefined;

export function openNewConnection(context: vscode.ExtensionContext, onCreated?: () => void): void {
  if (panel) {
    panel.reveal();
    return;
  }
  panel = vscode.window.createWebviewPanel(
    "messagefoundry.newConnection",
    "New Connection",
    vscode.ViewColumn.Active,
    { enableScripts: true },
  );
  panel.onDidDispose(() => (panel = undefined), null, context.subscriptions);
  panel.webview.onDidReceiveMessage(async (m: { command?: string; payload?: CreatePayload }) => {
    if (m?.command === "create" && m.payload) {
      await createConnection(m.payload, onCreated);
    } else if (m?.command === "cancel") {
      panel?.dispose();
    }
  });
  panel.webview.html = formHtml(panel.webview);
}

async function createConnection(p: CreatePayload, onCreated?: () => void): Promise<void> {
  const ws = workspaceDir();
  if (!ws) {
    void vscode.window.showErrorMessage("MessageFoundry: open a workspace folder first.");
    return;
  }
  // Required-field backstop (the webview validates too, but never trust the client). An inbound with
  // an empty router writes a module that fails registry.validate(), so guard it here as well.
  const name = p.name.trim();
  const partner = (p.partner || "").trim();
  const message = (p.message || "").trim();
  const router = (p.router || "").trim();
  const isInbound = p.kind === "mllp-in" || p.kind === "file-in";
  const missing: string[] = [];
  if (!name) missing.push("connection name");
  if (!partner) missing.push("partner");
  if (!message) missing.push("message type");
  if (isInbound && !router) missing.push("router");
  if (missing.length) {
    const label = missing.length === 1 ? "is" : "are";
    void vscode.window.showErrorMessage(`MessageFoundry: ${missing.join(", ")} ${label} required.`);
    return;
  }
  const dir = path.isAbsolute(configDir()) ? configDir() : path.join(ws, configDir());
  const fileName = `${name.replace(/[^A-Za-z0-9_-]/g, "_")}.py`;
  const target = vscode.Uri.file(path.join(dir, fileName));

  let exists = true;
  try {
    await vscode.workspace.fs.stat(target);
  } catch {
    exists = false;
  }
  if (exists) {
    void vscode.window.showErrorMessage(`MessageFoundry: ${fileName} already exists.`);
    return;
  }

  try {
    await vscode.workspace.fs.writeFile(target, Buffer.from(generateCode(p), "utf8"));
    const doc = await vscode.workspace.openTextDocument(target);
    await vscode.window.showTextDocument(doc);
    panel?.dispose();
    onCreated?.(); // refresh the Connections graph
    void vscode.window.showInformationMessage(`MessageFoundry: created ${name} in ${fileName}.`);
  } catch (e) {
    void vscode.window.showErrorMessage(`MessageFoundry: could not create connection — ${String(e)}`);
  }
}

function generateCode(p: CreatePayload): string {
  const q = (s: string): string => `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
  const router = (p.router || "").trim();
  const imports = new Set<string>();
  const body: string[] = [];

  if (p.kind === "mllp-out") {
    imports.add("MLLP").add("outbound");
    body.push(
      `outbound(${q(p.name)}, MLLP(host=${q(p.host || "127.0.0.1")}, port=${Number(p.port) || 2575}))`,
    );
  } else if (p.kind === "file-out") {
    imports.add("File").add("outbound");
    body.push(
      `outbound(${q(p.name)}, File(directory=${q(p.directory || "./out")}, filename=${q(p.filename || "{MSH-10}.hl7")}))`,
    );
  } else {
    // inbound (mllp-in | file-in)
    imports.add("inbound");
    let spec: string;
    if (p.kind === "mllp-in") {
      imports.add("MLLP");
      // Inbound takes only a port — the bind interface is the service-level [inbound].bind_host (set
      // per environment); a host on an inbound is a wiring error (review H-11). Mirrors New Route.
      spec = `MLLP(port=${Number(p.port) || 2575})`;
    } else {
      imports.add("File");
      spec = `File(directory=${q(p.directory || "./in")}, pattern=${q(p.pattern || "*.hl7")})`;
    }
    const extra: string[] = [];
    if (p.kind === "mllp-in") {
      if (p.ackMode && p.ackMode !== "original") {
        extra.push(`ack_mode=AckMode.${p.ackMode.toUpperCase()}`);
        imports.add("AckMode");
      }
      if (p.strict) {
        extra.push("strict=True");
      }
      if ((p.hl7Version || "").trim()) {
        extra.push(`hl7_version=${q((p.hl7Version || "").trim())}`);
      }
    }
    body.push(`inbound(${q(p.name)}, ${spec}, router=${q(router)}${extra.length ? ", " + extra.join(", ") : ""})`);

    if (p.scaffold) {
      const base = router.replace(/_router$/, "") || "msg";
      const handlerName = `${base}_handler`;
      imports.add("router").add("handler").add("Send");
      body.push(
        "",
        "",
        `@router(${q(router)})`,
        "def route(msg):",
        `    return [${q(handlerName)}]  # TODO: routing logic`,
        "",
        "",
        `@handler(${q(handlerName)})`,
        "def handle(msg):",
        "    # TODO: filter / transform",
        '    return None  # TODO: return Send("OB_...", msg) to an outbound',
      );
    } else {
      body.push(`# TODO: define router ${q(router)} (New Router) and its handler(s).`);
    }
  }

  return `from messagefoundry import ${[...imports].sort().join(", ")}\n\n${body.join("\n")}\n`;
}

function nonce(): string {
  let s = "";
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  for (let i = 0; i < 24; i++) {
    s += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return s;
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
    body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); padding: 12px 16px; max-width: 640px; }
    h2 { font-size: 15px; margin: 0 0 12px; }
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
    button:hover { background: var(--vscode-button-hoverBackground); }
    .hint { font-size: 11px; color: var(--vscode-descriptionForeground); margin-top: 4px; }
    .check { display: block; margin-top: 12px; font-size: 13px; }
    .check input { width: auto; margin-right: 6px; vertical-align: middle; }
    input.invalid, select.invalid { border-color: var(--vscode-inputValidation-errorBorder, var(--vscode-errorForeground)); }
    .error { display: none; margin-top: 10px; font-size: 12px; color: var(--vscode-errorForeground); }
  </style>
</head>
<body>
  <h2>New Connection</h2>

  <label for="kind">Type</label>
  <select id="kind">
    <option value="mllp-in">MLLP — Inbound (IB) · listen for messages</option>
    <option value="mllp-out">MLLP — Outbound (OB) · send messages</option>
    <option value="file-in">File — Inbound (FILE-IN) · poll a folder</option>
    <option value="file-out">File — Outbound (FILE-OUT) · write to a folder</option>
    <option value="" disabled>SFTP / SOAP / REST / DB — coming soon</option>
  </select>

  <div class="row">
    <div><label for="partner">Partner</label><input id="partner" placeholder="ACME" /></div>
    <div><label for="message">Message type</label><input id="message" placeholder="ADT" /></div>
  </div>

  <label for="name">Connection name</label>
  <input id="name" class="name" />
  <div class="hint">Auto-built as [TYPE]_[PARTNER]_[MESSAGE]; edit if you need to.</div>

  <div id="mllp">
    <div class="row">
      <div id="host-col"><label for="host">Host</label><input id="host" /></div>
      <div><label for="port">Port</label><input id="port" value="2575" /></div>
    </div>
  </div>

  <div id="file">
    <div><label for="directory">Directory</label><input id="directory" /></div>
    <div id="file-in-only"><label for="pattern">Filename pattern</label><input id="pattern" value="*.hl7" /></div>
    <div id="file-out-only"><label for="filename">Output filename</label><input id="filename" value="{MSH-10}.hl7" /></div>
  </div>

  <div id="router-row"><label for="router">Router</label><input id="router" placeholder="acme_router" />
    <div class="hint">The inbound feeds this router.</div>
  </div>

  <div id="mllp-in-opts">
    <div class="row">
      <div><label for="ackMode">ACK mode</label>
        <select id="ackMode">
          <option value="original">original (AA/AE/AR)</option>
          <option value="enhanced">enhanced (CA/CE/CR)</option>
          <option value="none">none</option>
        </select>
      </div>
      <div><label for="hl7Version">HL7 version (optional)</label><input id="hl7Version" placeholder="2.5.1" /></div>
    </div>
    <label class="check"><input type="checkbox" id="strict" /> Strict validation (hl7apy)</label>
  </div>

  <label class="check" id="scaffold-row"><input type="checkbox" id="scaffold" /> Also scaffold the router + a handler stub</label>

  <div id="error" class="error"></div>

  <div class="actions">
    <button id="create">Create</button>
    <button id="cancel" class="secondary">Cancel</button>
  </div>

  <script nonce="${n}">
    const vscode = acquireVsCodeApi();
    const $ = (id) => document.getElementById(id);
    const kind = $('kind'), partner = $('partner'), message = $('message'), name = $('name'), router = $('router');
    const errorEl = $('error');
    let nameEdited = false;
    name.addEventListener('input', () => { nameEdited = true; });

    const PREFIX = { 'mllp-in': 'IB', 'mllp-out': 'OB', 'file-in': 'FILE-IN', 'file-out': 'FILE-OUT' };
    function isInbound() { return kind.value === 'mllp-in' || kind.value === 'file-in'; }
    function isMllp() { return kind.value === 'mllp-in' || kind.value === 'mllp-out'; }

    function refreshName() {
      if (nameEdited) return;
      const p = (partner.value || 'Partner').trim();
      const m = (message.value || 'MSG').trim();
      name.value = PREFIX[kind.value] + '_' + p + '_' + m;
    }
    function refreshVisibility() {
      $('mllp').style.display = isMllp() ? '' : 'none';
      // Host is an OUTBOUND-only field — inbound binds via the service [inbound].bind_host (H-11).
      $('host-col').style.display = kind.value === 'mllp-out' ? '' : 'none';
      $('file').style.display = isMllp() ? 'none' : '';
      $('file-in-only').style.display = kind.value === 'file-in' ? '' : 'none';
      $('file-out-only').style.display = kind.value === 'file-out' ? '' : 'none';
      $('router-row').style.display = isInbound() ? '' : 'none';
      $('mllp-in-opts').style.display = kind.value === 'mllp-in' ? '' : 'none';
      $('scaffold-row').style.display = isInbound() ? '' : 'none';
      if (kind.value === 'mllp-out') $('host').value = $('host').value || '127.0.0.1';
      $('directory').value = $('directory').value || (isInbound() ? './in' : './out');
    }

    // Required: partner, message, name always; router only for inbound. Mark offenders, list them,
    // and block Create — an empty router would write a module that fails the engine's validate().
    function validate() {
      const checks = [
        [partner, 'Partner', true],
        [message, 'Message type', true],
        [name, 'Connection name', true],
        [router, 'Router', isInbound()],
      ];
      const need = [];
      for (const [el, label, required] of checks) {
        const bad = required && !(el.value || '').trim();
        el.classList.toggle('invalid', bad);
        if (bad) need.push(label);
      }
      if (need.length) {
        errorEl.textContent = 'Required: ' + need.join(', ') + '.';
        errorEl.style.display = '';
        return false;
      }
      errorEl.style.display = 'none';
      return true;
    }

    for (const el of [kind, partner, message]) {
      el.addEventListener('input', () => { refreshName(); refreshVisibility(); });
    }
    // Clear a field's error as the user fixes it; re-validate live once an error is showing.
    for (const el of [partner, message, name, router]) {
      el.addEventListener('input', () => {
        el.classList.remove('invalid');
        if (errorEl.style.display !== 'none') validate();
      });
    }
    kind.addEventListener('change', () => { if (errorEl.style.display !== 'none') validate(); });
    refreshName();
    refreshVisibility();

    $('create').addEventListener('click', () => {
      if (!validate()) return;
      vscode.postMessage({ command: 'create', payload: {
        kind: kind.value,
        name: name.value,
        partner: partner.value,
        message: message.value,
        host: $('host').value,
        port: $('port').value,
        router: router.value,
        directory: $('directory').value,
        pattern: $('pattern').value,
        filename: $('filename').value,
        ackMode: $('ackMode').value,
        strict: $('strict').checked,
        hl7Version: $('hl7Version').value,
        scaffold: $('scaffold').checked,
      }});
    });
    $('cancel').addEventListener('click', () => vscode.postMessage({ command: 'cancel' }));
  </script>
</body>
</html>`;
}
