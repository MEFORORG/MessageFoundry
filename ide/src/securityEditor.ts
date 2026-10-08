// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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
import { STARTUP_BANNERS, openChannel, postToWebview } from "./webviewMessaging";
import { FIELDS, securityEditorScript } from "./securityEditorWebview";

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
    postToWebview(current.webview, { command: "error", message: String(e) });
    return;
  }
  await refresh(current);
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
