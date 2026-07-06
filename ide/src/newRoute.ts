// "New Route Wizard" — a stepped webview that builds an end-to-end interface in one go:
// Inbound connection -> Router -> Handler -> Outbound connection, all wired (router returns the
// handler; handler Sends to the OB), generated into a single config module. Required fields are
// validated before each step advances, so the wizard never emits invalid config.
import * as path from "node:path";
import * as vscode from "vscode";
import { configDir, workspaceDir } from "./cli";

interface RoutePayload {
  ib: { kind: "mllp-in" | "file-in"; name: string; port?: string; directory?: string; pattern?: string };
  router: string;
  handler: string;
  ob: { kind: "mllp-out" | "file-out"; name: string; host?: string; port?: string; directory?: string; filename?: string };
}

let panel: vscode.WebviewPanel | undefined;

export function openNewRoute(context: vscode.ExtensionContext, onCreated?: () => void): void {
  if (panel) {
    panel.reveal();
    return;
  }
  panel = vscode.window.createWebviewPanel("messagefoundry.newRoute", "New Route", vscode.ViewColumn.Active, {
    enableScripts: true,
  });
  panel.onDidDispose(() => (panel = undefined), null, context.subscriptions);
  panel.webview.onDidReceiveMessage(async (m: { command?: string; payload?: RoutePayload }) => {
    if (m?.command === "create" && m.payload) {
      await createRoute(m.payload, onCreated);
    } else if (m?.command === "cancel") {
      panel?.dispose();
    }
  });
  panel.webview.html = wizardHtml(panel.webview);
}

async function createRoute(p: RoutePayload, onCreated?: () => void): Promise<void> {
  const ws = workspaceDir();
  if (!ws) {
    void vscode.window.showErrorMessage("MessageFoundry: open a workspace folder first.");
    return;
  }
  // Server-side guard mirroring the form's validation — never write invalid config.
  if (!p.ib.name.trim() || !p.router.trim() || !p.handler.trim() || !p.ob.name.trim()) {
    void vscode.window.showErrorMessage("MessageFoundry: inbound/router/handler/outbound names are all required.");
    return;
  }
  const dir = path.isAbsolute(configDir()) ? configDir() : path.join(ws, configDir());
  const fileName = `${p.ib.name.trim().replace(/[^A-Za-z0-9_-]/g, "_")}.py`;
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
    await vscode.workspace.fs.writeFile(target, Buffer.from(generateRouteCode(p), "utf8"));
    const doc = await vscode.workspace.openTextDocument(target);
    await vscode.window.showTextDocument(doc);
    panel?.dispose();
    onCreated?.();
    void vscode.window.showInformationMessage(`MessageFoundry: created route ${p.ib.name.trim()} → ${p.ob.name.trim()}.`);
  } catch (e) {
    void vscode.window.showErrorMessage(`MessageFoundry: could not create the route — ${String(e)}`);
  }
}

function generateRouteCode(p: RoutePayload): string {
  const q = (s: string): string => `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
  const imports = new Set<string>(["inbound", "outbound", "router", "handler", "Send"]);

  let ibSpec: string;
  if (p.ib.kind === "mllp-in") {
    imports.add("MLLP");
    // Inbound takes only a port — the bind interface is a service setting ([inbound].bind_host),
    // set per environment by the operator, never authored here.
    ibSpec = `MLLP(port=${Number(p.ib.port) || 2575})`;
  } else {
    imports.add("File");
    ibSpec = `File(directory=${q(p.ib.directory || "./in")}, pattern=${q(p.ib.pattern || "*.hl7")})`;
  }
  let obSpec: string;
  if (p.ob.kind === "mllp-out") {
    imports.add("MLLP");
    obSpec = `MLLP(host=${q(p.ob.host || "127.0.0.1")}, port=${Number(p.ob.port) || 2575})`;
  } else {
    imports.add("File");
    obSpec = `File(directory=${q(p.ob.directory || "./out")}, filename=${q(p.ob.filename || "{MSH-10}.hl7")})`;
  }

  const body = [
    `inbound(${q(p.ib.name)}, ${ibSpec}, router=${q(p.router)})`,
    `outbound(${q(p.ob.name)}, ${obSpec})`,
    "",
    "",
    `@router(${q(p.router)})`,
    "def route(msg):",
    `    return [${q(p.handler)}]  # TODO: routing logic`,
    "",
    "",
    `@handler(${q(p.handler)})`,
    "def handle(msg):",
    "    # TODO: filter / transform",
    `    return Send(${q(p.ob.name)}, msg)`,
  ];
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

function wizardHtml(webview: vscode.Webview): string {
  const n = nonce();
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta http-equiv="Content-Security-Policy"
        content="default-src 'none'; style-src ${webview.cspSource} 'unsafe-inline'; script-src 'nonce-${n}';" />
  <style>
    body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); padding: 12px 16px; max-width: 640px; }
    h2 { font-size: 15px; margin: 0 0 2px; }
    .steps { font-size: 12px; color: var(--vscode-descriptionForeground); margin-bottom: 12px; }
    label { display: block; font-size: 12px; color: var(--vscode-descriptionForeground); margin: 10px 0 2px; }
    input, select { width: 100%; box-sizing: border-box; padding: 5px 8px; font-family: inherit; font-size: 13px;
      color: var(--vscode-input-foreground); background: var(--vscode-input-background);
      border: 1px solid var(--vscode-input-border, var(--vscode-panel-border)); border-radius: 2px; }
    .row { display: flex; gap: 12px; } .row > div { flex: 1; }
    .name { font-family: var(--vscode-editor-font-family, monospace); }
    .hint { font-size: 11px; color: var(--vscode-descriptionForeground); margin-top: 4px; }
    section { display: none; } section.active { display: block; }
    .footer { margin-top: 18px; display: flex; gap: 8px; align-items: center; }
    button { font-family: inherit; color: var(--vscode-button-foreground); background: var(--vscode-button-background);
      border: none; padding: 6px 14px; cursor: pointer; border-radius: 2px; }
    button.secondary { color: var(--vscode-button-secondaryForeground); background: var(--vscode-button-secondaryBackground); }
    button:hover { background: var(--vscode-button-hoverBackground); }
    button[disabled] { opacity: .5; cursor: default; }
    .err { color: var(--vscode-errorForeground); font-size: 12px; margin-left: auto; }
    pre { background: var(--vscode-textCodeBlock-background, rgba(127,127,127,.1)); border: 1px solid var(--vscode-panel-border);
      border-radius: 3px; padding: 8px; font-family: var(--vscode-editor-font-family, monospace); font-size: 12px; overflow: auto; }
  </style>
</head>
<body>
  <h2>New Route</h2>
  <div class="steps" id="stepLabel"></div>

  <section data-step="ib">
    <label for="ibKind">Inbound type</label>
    <select id="ibKind">
      <option value="mllp-in">MLLP — listen (IB)</option>
      <option value="file-in">File — poll a folder (FILE-IN)</option>
    </select>
    <div class="row">
      <div><label for="ibPartner">Partner</label><input id="ibPartner" placeholder="ACME" /></div>
      <div><label for="ibMessage">Message type</label><input id="ibMessage" placeholder="ADT" /></div>
    </div>
    <label for="ibName">Inbound name</label><input id="ibName" class="name" />
    <div id="ibMllp">
      <label for="ibPort">Port</label><input id="ibPort" value="2575" />
      <div class="hint">Listens on the service's configured interface ([inbound].bind_host, set per
        environment by the operator) — you only choose the port.</div>
    </div>
    <div id="ibFile">
      <div><label for="ibDir">Directory</label><input id="ibDir" value="./in" /></div>
      <label for="ibPattern">Filename pattern</label><input id="ibPattern" value="*.hl7" />
    </div>
  </section>

  <section data-step="router">
    <label for="routerName">Router name</label><input id="routerName" class="name" />
    <div class="hint">The inbound feeds this router; the wizard generates a stub that returns the handler.</div>
  </section>

  <section data-step="handler">
    <label for="handlerName">Handler name</label><input id="handlerName" class="name" />
    <div class="hint">Generated as a stub (filter/transform TODO) that Sends to the outbound below.</div>
  </section>

  <section data-step="ob">
    <label for="obKind">Outbound type</label>
    <select id="obKind">
      <option value="mllp-out">MLLP — send (OB)</option>
      <option value="file-out">File — write to a folder (FILE-OUT)</option>
    </select>
    <div class="row">
      <div><label for="obPartner">Partner</label><input id="obPartner" placeholder="EPIC" /></div>
      <div><label for="obMessage">Message type</label><input id="obMessage" placeholder="ADT" /></div>
    </div>
    <label for="obName">Outbound name</label><input id="obName" class="name" />
    <div id="obMllp" class="row">
      <div><label for="obHost">Host</label><input id="obHost" value="127.0.0.1" /></div>
      <div><label for="obPort">Port</label><input id="obPort" value="2575" /></div>
    </div>
    <div id="obFile">
      <div><label for="obDir">Directory</label><input id="obDir" value="./out" /></div>
      <label for="obFilename">Output filename</label><input id="obFilename" value="{MSH-10}.hl7" />
    </div>
  </section>

  <section data-step="review">
    <div class="hint">Review the generated route, then create it.</div>
    <pre id="preview"></pre>
  </section>

  <div class="footer">
    <button id="back" class="secondary">Back</button>
    <button id="next">Next</button>
    <button id="create" style="display:none">Create the route</button>
    <button id="cancel" class="secondary">Cancel</button>
    <span class="err" id="err"></span>
  </div>

  <script nonce="${n}">
    const vscode = acquireVsCodeApi();
    const $ = (id) => document.getElementById(id);
    const STEPS = ['ib', 'router', 'handler', 'ob', 'review'];
    const TITLES = { ib: 'Inbound connection', router: 'Router', handler: 'Handler', ob: 'Outbound connection', review: 'Review' };
    let step = 0;
    const edited = {};
    function markEdited(id) { $(id).addEventListener('input', () => { edited[id] = true; }); }
    ['ibName', 'obName', 'routerName', 'handlerName'].forEach(markEdited);

    const sect = (s) => document.querySelector('section[data-step="' + s + '"]');
    const lc = (s) => s.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');

    function recompute() {
      const ibP = $('ibPartner').value.trim() || 'Partner', ibM = $('ibMessage').value.trim() || 'MSG';
      const ibPrefix = $('ibKind').value === 'mllp-in' ? 'IB' : 'FILE-IN';
      if (!edited.ibName) $('ibName').value = ibPrefix + '_' + ibP + '_' + ibM;
      if (!edited.routerName) $('routerName').value = lc(ibP + '_' + ibM) + '_router';
      if (!edited.handlerName) $('handlerName').value = lc(ibP + '_' + ibM) + '_handler';
      if (!edited.obName) {
        const obP = $('obPartner').value.trim() || 'Dest', obM = ($('obMessage').value.trim() || ibM);
        $('obName').value = ($('obKind').value === 'mllp-out' ? 'OB' : 'FILE-OUT') + '_' + obP + '_' + obM;
      }
      $('ibMllp').style.display = $('ibKind').value === 'mllp-in' ? 'block' : 'none';
      $('ibFile').style.display = $('ibKind').value === 'file-in' ? 'block' : 'none';
      $('obMllp').style.display = $('obKind').value === 'mllp-out' ? 'flex' : 'none';
      $('obFile').style.display = $('obKind').value === 'file-out' ? 'block' : 'none';
    }
    for (const id of ['ibKind', 'ibPartner', 'ibMessage', 'obKind', 'obPartner', 'obMessage']) {
      $(id).addEventListener('input', recompute);
    }

    function payload() {
      return {
        ib: { kind: $('ibKind').value, name: $('ibName').value.trim(), port: $('ibPort').value,
              directory: $('ibDir').value, pattern: $('ibPattern').value },
        router: $('routerName').value.trim(),
        handler: $('handlerName').value.trim(),
        ob: { kind: $('obKind').value, name: $('obName').value.trim(), host: $('obHost').value, port: $('obPort').value,
              directory: $('obDir').value, filename: $('obFilename').value },
      };
    }

    function validate(s) {
      const p = payload();
      if (s === 'ib') {
        if (!$('ibPartner').value.trim() || !$('ibMessage').value.trim()) return 'Partner and message type are required.';
        if (!p.ib.name) return 'Inbound name is required.';
        if (p.ib.kind === 'mllp-in' && !p.ib.port.trim()) return 'Port is required.';
        if (p.ib.kind === 'file-in' && !p.ib.directory.trim()) return 'Directory is required.';
      } else if (s === 'router') { if (!p.router) return 'Router name is required.'; }
      else if (s === 'handler') { if (!p.handler) return 'Handler name is required.'; }
      else if (s === 'ob') {
        if (!$('obPartner').value.trim() || !$('obMessage').value.trim()) return 'Partner and message type are required.';
        if (!p.ob.name) return 'Outbound name is required.';
        if (p.ob.kind === 'mllp-out' && !p.ob.port.trim()) return 'Port is required.';
        if (p.ob.kind === 'file-out' && !p.ob.directory.trim()) return 'Directory is required.';
      }
      return '';
    }

    function render() {
      STEPS.forEach((s, i) => sect(s).classList.toggle('active', i === step));
      $('stepLabel').textContent = 'Step ' + (step + 1) + ' of ' + STEPS.length + ': ' + TITLES[STEPS[step]];
      $('back').disabled = step === 0;
      const onReview = STEPS[step] === 'review';
      $('next').style.display = onReview ? 'none' : '';
      $('create').style.display = onReview ? '' : 'none';
      $('err').textContent = '';
      if (onReview) $('preview').textContent = previewText();
    }

    function previewText() {
      const p = payload();
      const ib = p.ib.kind === 'mllp-in'
        ? 'MLLP(port=' + (p.ib.port || '2575') + ')'
        : 'File(directory="' + (p.ib.directory || './in') + '", pattern="' + (p.ib.pattern || '*.hl7') + '")';
      const ob = p.ob.kind === 'mllp-out'
        ? 'MLLP(host="' + (p.ob.host || '127.0.0.1') + '", port=' + (p.ob.port || '2575') + ')'
        : 'File(directory="' + (p.ob.directory || './out') + '", filename="' + (p.ob.filename || '{MSH-10}.hl7') + '")';
      return 'inbound("' + p.ib.name + '", ' + ib + ', router="' + p.router + '")\\n'
        + 'outbound("' + p.ob.name + '", ' + ob + ')\\n\\n'
        + '@router("' + p.router + '")  ->  ["' + p.handler + '"]\\n'
        + '@handler("' + p.handler + '")  ->  Send("' + p.ob.name + '", msg)';
    }

    $('next').addEventListener('click', () => {
      const msg = validate(STEPS[step]);
      if (msg) { $('err').textContent = msg; return; }
      step = Math.min(step + 1, STEPS.length - 1);
      render();
    });
    $('back').addEventListener('click', () => { step = Math.max(step - 1, 0); render(); });
    $('cancel').addEventListener('click', () => vscode.postMessage({ command: 'cancel' }));
    $('create').addEventListener('click', () => vscode.postMessage({ command: 'create', payload: payload() }));

    recompute();
    render();
  </script>
</body>
</html>`;
}
