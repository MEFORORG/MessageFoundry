// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// [security] posture editor (ADR 0118) — a webview form that manages the plain-language, secure-by-
// default switches in the service-settings TOML's `[security]` section by shelling the
// `messagefoundry security show|set` CLI (which validates + writes comment-preservingly, and REJECTS the
// relocated legacy keys). This is the SOLE authoring surface for `[security]`; the web console is
// read-only (GET /security/posture). The switches are pure data (booleans/ints/strings, no code), so —
// like connections.toml (ADR 0007) and [[alerts.rules]] (ADR 0014) — they are GUI-manageable.
//
// Every switch defaults to the SECURE position; when the operator moves one to its insecure value, or a
// session limit above its default, the form shows a plain-language loosening warning in place (CISA
// "make deviations from safe defaults obvious"). A change takes effect on the next engine restart (the TOML is read at startup).
import * as fs from "node:fs";
import * as vscode from "vscode";
import { runJson, workspaceDir, writerCheckSetting } from "./cli";
import { STARTUP_BANNERS, openChannel, postToWebview } from "./webviewMessaging";
import { FIELDS, securityEditorScript } from "./securityEditorWebview";
import {
  ShownFile,
  saveUpdatesProblem,
  securityConfigInput,
  securityConfigTarget,
  securitySetArgs,
  securityShowArgs,
} from "./securityEditorModel";

interface ShowResult {
  values: Record<string, unknown>;
  set: string[];
  defaults: Record<string, unknown>;
  loosenings: { switch: string; risk: string }[];
}

// The open panel and the file its form shows. The file is held per panel, so a late refresh from a
// disposed panel can neither set it nor save through it.
let panel: { readonly view: vscode.WebviewPanel; readonly shown: ShownFile } | undefined;

/** Open the [security] editor: loads the current switches + secure defaults and saves edits via the CLI. */
export async function openSecurityEditor(context: vscode.ExtensionContext): Promise<void> {
  const ws = workspaceDir();
  if (!ws) {
    void vscode.window.showInformationMessage("MessageFoundry: open a workspace folder first.");
    return;
  }
  // Refused at the command, as newRoute.ts refuseUntrusted() does, so no panel opens to go stale
  // after a trust grant. configPath() checks again, before any file-system call.
  if (!vscode.workspace.isTrusted) {
    void vscode.window.showWarningMessage(
      "MessageFoundry: trust this workspace to edit its security settings. The editor reads the workspace's folders to check its settings path.",
    );
    return;
  }
  if (panel) {
    panel.view.reveal(vscode.ViewColumn.Active);
    void refresh(panel.view, panel.shown);
    return;
  }
  const current = vscode.window.createWebviewPanel(
    "messagefoundry.securityEditor",
    "Security Settings",
    vscode.ViewColumn.Active,
    { enableScripts: true },
  );
  const shown = new ShownFile();
  const opened = { view: current, shown };
  panel = opened;
  current.onDidDispose(
    () => {
      shown.dispose();
      if (panel === opened) {
        panel = undefined;
      }
    },
    null,
    context.subscriptions,
  );
  current.webview.onDidReceiveMessage(
    async (m: { command?: string; updates?: unknown }) => {
      if (m?.command === "save") {
        // Checked here as well as in the webview: this is what reaches the file (BACKLOG #5411).
        const problem = saveUpdatesProblem(m.updates, FIELDS);
        if (problem !== null) {
          postToWebview(current.webview, { command: "error", message: `Not saved: ${problem}.` });
          return;
        }
        await save(m.updates as Record<string, unknown>, current, shown);
      } else if (m?.command === "cancel") {
        current.dispose();
      }
    },
  );
  current.webview.html = formHtml(current.webview);
  await refresh(current, shown);
}

/** The service-settings file to read and write, within the rules of securityConfigTarget
 *  (BACKLOG #5411), or undefined after the refusal is posted to the webview. */
function configPath(ws: string, current: vscode.WebviewPanel): string | undefined {
  // Trust is passed in and checked first, so an untrusted workspace makes no file-system call here.
  const seen = vscode.workspace.getConfiguration("messagefoundry").inspect("serviceConfig");
  // A value cli.ts's containment dropped (BACKLOG #5404) is checked as written; securityConfigInput.
  const { value, fromWorkspace } = securityConfigInput(seen, writerCheckSetting("serviceConfig"));
  const target = securityConfigTarget(ws, value, { fromWorkspace, trusted: vscode.workspace.isTrusted }, {
    lstat: fs.lstatSync,
    realpath: fs.realpathSync.native,
    fileId: (p: string): string => {
      const st = fs.statSync(p, { bigint: true });
      return `${st.dev}:${st.ino}`;
    },
  });
  if (!target.ok) {
    postToWebview(current.webview, { command: "error", message: `${target.problem}. Nothing was read or written.` });
    return undefined;
  }
  return target.path;
}

/** Re-read `security show` and push the current state (values + defaults + loosenings) to the webview. */
async function refresh(current: vscode.WebviewPanel, shown: ShownFile, resolved?: string): Promise<void> {
  const ws = workspaceDir();
  if (!ws || shown.disposed) {
    return;
  }
  shown.clear();
  // After a save, the file just written, so the state shown is that file's even if the setting moved.
  const file = resolved ?? configPath(ws, current);
  if (file === undefined) {
    return;
  }
  try {
    const state = await runJson<ShowResult>(securityShowArgs(file), ws);
    if (shown.disposed) {
      return;
    }
    shown.set(file);
    postToWebview(current.webview, { command: "state", state });
  } catch (e) {
    postToWebview(current.webview, { command: "error", message: String(e) });
  }
}

/** Save the edited switches: `updates` maps each key to its value, or null to reset it to the secure
 *  default (the CLI drops the key). Validation errors surface inline; the file is only touched on success. */
async function save(
  updates: Record<string, unknown>,
  current: vscode.WebviewPanel,
  shown: ShownFile,
): Promise<void> {
  const ws = workspaceDir();
  if (!ws || shown.disposed) {
    return;
  }
  const file = configPath(ws, current);
  if (file === undefined) {
    return;
  }
  if (!shown.matches(file)) {
    postToWebview(current.webview, {
      command: "error",
      message:
        "Not saved: the settings file this form shows is not the one messagefoundry.serviceConfig names now. " +
        "Run Edit Security Settings to read the file again.",
    });
    return;
  }
  try {
    await runJson(securitySetArgs(file, updates), ws);
  } catch (e) {
    postToWebview(current.webview, { command: "error", message: String(e) });
    return;
  }
  await refresh(current, shown, file);
  void vscode.window.showInformationMessage(
    "MessageFoundry: saved [security] settings. Restart the engine to apply (read at startup).",
  );
}

function formHtml(webview: vscode.Webview): string {
  const { nonce: n, token } = openChannel(webview);
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
  ${STARTUP_BANNERS}
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

  <script nonce="${n}">${securityEditorScript(token, FIELDS)}
  </script>
</body>
</html>`;
}
