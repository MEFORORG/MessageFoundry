// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Connection editor (ADR 0007) — a webview form that creates/edits a connection in the workspace's
// connections.toml by shelling the `messagefoundry connection upsert|remove` CLI (which validates +
// writes comment-preservingly). Logic (routers/handlers) stays in .py; this edits transport config.
// A connection authored in .py is read-only here (it isn't in `connection list`) — the gear opens its
// source instead. After a save the graph refreshes and a Promote is offered.
import * as vscode from "vscode";
import { configDir, runJson, workspaceDir } from "./cli";
import { type ConnObj, nameCollisionError, planSave } from "./connectionMerge";
import { type FieldGroup, buildForm } from "./connectionForm";
import { connectionSchema } from "./connectionSchema";
import { openChannel, postToWebview } from "./webviewMessaging";
import { connectionEditorScript } from "./connectionEditorWebview";

// The ConnObj shape lives in the pure connectionMerge.ts (the mocha-run unit tests import it and
// must not pull vscode); re-exported here so existing consumers keep their import path.
export type { ConnObj } from "./connectionMerge";

// Fallback only. The transport list now comes from the installed engine (`connection schema --json`,
// 11 transports); this stale copy is what the form falls back to when the engine cannot describe
// itself -- an engine predating the verb, an untrusted workspace, a broken interpreter -- so the
// editor keeps working rather than rendering an empty picker.
const TRANSPORTS = ["mllp", "tcp", "file", "rest", "database", "database_poll", "soap", "sftp", "ftp"];

/**
 * Ask the engine to describe itself and build the field groups for one transport/direction. Returns
 * undefined when the schema is unavailable for ANY reason: a missing catalogue must degrade the form
 * to its legacy free-text rows, never block editing a connection.
 */
export async function formSchemaFor(
  cwd: string,
  transport: string,
  direction: "inbound" | "outbound",
  settings: Record<string, unknown>,
): Promise<FormSchema | undefined> {
  try {
    const schema = await connectionSchema(cwd);
    const transports = Object.keys(schema.transports).sort();
    return { transports, groups: buildForm(schema, transport, direction, settings) };
  } catch {
    return undefined; // logged by the caller's status surface; the form still opens
  }
}

/** Sibling connections in the same connections.toml, for the customEditor's picker (#221b). When
 *  present, the form renders a "＋ New / <name>…" dropdown above the title so the whole file's
 *  connections are reachable from the one custom editor; omitted for the command-opened single form. */
export interface SiblingPicker {
  names: string[];
  current: string | null; // the connection currently shown (null → the blank "New" form)
}

let panel: vscode.WebviewPanel | undefined;

export interface EditorOpts {
  routers: string[];
  editName?: string; // edit an existing (TOML-authored) connection; omit to create
  cloneFrom?: string; // #175: open CREATE mode pre-filled from this connection (a new name is required)
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

  // Clone (#175) opens CREATE mode pre-filled from an existing connection (a new name is required);
  // edit opens in-place. Both load the source from `connection list`.
  const lookupName = opts.editName ?? opts.cloneFrom;
  const clone = opts.editName == null && opts.cloneFrom != null;
  let initial: ConnObj | undefined;
  if (lookupName) {
    let entries: ConnObj[];
    try {
      entries = await runJson<ConnObj[]>(["connection", "list", "--config", configDir()], ws);
    } catch (e) {
      void vscode.window.showErrorMessage(`MessageFoundry: could not read connections — ${String(e)}`);
      return;
    }
    initial = entries.find((c) => c.name === lookupName);
    if (!initial) {
      void vscode.window.showInformationMessage(
        `MessageFoundry: ${lookupName} is authored in code (a .py module), not connections.toml — ` +
          "the GUI manages connections.toml connections.",
      );
      return;
    }
  }

  if (panel) {
    panel.dispose(); // reopen fresh for the new target
  }
  panel = vscode.window.createWebviewPanel(
    "messagefoundry.connectionEditor",
    clone ? "New Connection (clone)" : initial ? `Edit ${initial.name}` : "New Connection",
    vscode.ViewColumn.Active,
    { enableScripts: true },
  );
  const current = panel;
  current.onDidDispose(() => {
    if (panel === current) {
      panel = undefined;
    }
  }, null, context.subscriptions);

  current.webview.onDidReceiveMessage(
    async (m: {
      command?: string;
      conn?: ConnObj;
      name?: string;
      transport?: string;
      direction?: string;
      settings?: Record<string, unknown>;
    }) => {
      if (m?.command === "save" && m.conn) {
        await save(m.conn, current, { editName: opts.editName, cloneFrom: opts.cloneFrom }, opts.onSaved);
      } else if (m?.command === "delete" && m.name) {
        await remove(m.name, current, opts.onSaved);
      } else if (m?.command === "cancel") {
        current.dispose();
      } else if (
        m?.command === "fields" &&
        typeof m.transport === "string" &&
        (m.direction === "inbound" || m.direction === "outbound")
      ) {
        // Rebuild the descriptors HERE, so the grouping/typing rules live in the one tested module
        // rather than being reimplemented in webview script.
        const rebuilt = await formSchemaFor(ws, m.transport, m.direction, m.settings ?? {});
        if (rebuilt) {
          void postToWebview(current.webview, { command: "fields", groups: rebuilt.groups });
        }
      }
    },
  );

  // Describe the engine before drawing, so the form opens already showing this engine's real fields.
  // Undefined degrades to the legacy free-text rows rather than blocking the editor.
  const form = await formSchemaFor(
    ws,
    initial?.transport ?? "mllp",
    initial?.direction ?? "inbound",
    (initial?.settings as Record<string, unknown>) ?? {},
  );
  current.webview.html = connectionFormHtml(
    current.webview,
    opts.routers,
    initial,
    undefined,
    clone,
    form,
  );
}

async function save(
  conn: ConnObj,
  current: vscode.WebviewPanel,
  ctx: { editName?: string; cloneFrom?: string },
  onSaved?: () => void,
): Promise<void> {
  const ws = workspaceDir();
  if (!ws) {
    return;
  }
  // #234: the form posts only the fields it renders, but `connection upsert` is a full replace —
  // merge the post over a save-time FRESH `connection list` (the stated merge-source policy, shared
  // with configEditors.ts via planSave) so non-rendered keys (schedule, shard, allowlist, …) survive
  // an edit AND a clone. A list failure aborts the save: upserting the bare post would re-strip
  // every non-rendered key, so failing closed is the only non-destructive option.
  let entries: ConnObj[];
  try {
    entries = await runJson<ConnObj[]>(["connection", "list", "--config", configDir()], ws);
  } catch (e) {
    postToWebview(current.webview, {
      command: "error",
      message: `could not re-read connections.toml before saving (nothing was written) — ${String(e)}`,
    });
    return;
  }
  const plan = planSave(entries, conn, {
    mergeFrom: ctx.editName ?? ctx.cloneFrom,
    editingName: ctx.editName,
  });
  if (plan.collision) {
    // Create/clone under an existing name would silently destroy that connection (full replace).
    postToWebview(current.webview, { command: "error", message: nameCollisionError(plan.collision) });
    return;
  }
  try {
    await runJson(
      ["connection", "upsert", "--config", configDir(), "--data", JSON.stringify(plan.conn)],
      ws,
    );
  } catch (e) {
    // Surface the validation/egress error inline so the user can fix the form (file was not changed).
    postToWebview(current.webview, { command: "error", message: String(e) });
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
    postToWebview(current.webview, { command: "error", message: String(e) });
    return;
  }
  current.dispose();
  onSaved?.();
  void vscode.window.showInformationMessage(`MessageFoundry: removed ${name} from connections.toml.`);
}

/**
 * The transports and settings the INSTALLED engine declares, or undefined when it could not be
 * fetched (an engine predating `connection schema`, an untrusted workspace, a broken interpreter).
 * Undefined is a supported state, not an error: the form falls back to the legacy free-text
 * key/value rows so the editor still works against an older engine.
 */
export interface FormSchema {
  transports: string[];
  groups: FieldGroup[];
}

export function connectionFormHtml(
  webview: vscode.Webview,
  routers: string[],
  initial?: ConnObj,
  siblings?: SiblingPicker,
  clone?: boolean,
  form?: FormSchema,
): string {
  const { nonce: n, token } = openChannel(webview);
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
  <div id="conn-picker-row" style="display:none;margin-bottom:10px;">
    <label for="connPicker">Connection in this file</label>
    <select id="connPicker"></select>
  </div>
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
      <div><label for="maxAttempts">Retry max attempts</label><input id="maxAttempts" />
        <div class="hint">Blank inherits the <code>[delivery]</code> default, which is
        <strong>finite</strong>. It does <strong>not</strong> mean forever. To never give up, type
        <code>forever</code>: it is saved as <code>max_attempts = "forever"</code> under this
        connection's <code>[outbound.retry]</code> table (BACKLOG #1217).</div>
      </div>
    </div>
  </div>

  <div id="error" class="error"></div>

  <div class="actions">
    <button id="save">Save</button>
    <button id="cancel" class="secondary">Cancel</button>
    <button id="delete" class="danger" style="display:none;">Remove…</button>
  </div>

  <script nonce="${n}">${connectionEditorScript(token, {
    initial,
    routers,
    transports: form?.transports?.length ? form.transports : TRANSPORTS,
    fieldGroups: form?.groups ?? null,
    siblings,
    clone,
  })}
  </script>
</body>
</html>`;
}
