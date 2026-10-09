// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
// Code-set (translation table) grid editor — a webview that creates/edits a codesets/<name>.csv by
// shelling the `messagefoundry codeset show|upsert|rename|remove` CLI (which validates + writes the
// CSV, then re-loads it as the post-write authority). A code set is read-only reference data: the
// first column is the lookup key, every cell is a string (CSV-first). This grid is exactly that —
// rows×columns of strings, key column pinned first.
//
// Mirrors connectionEditor.ts: a single WebviewPanel, scripts enabled, a nonce'd CSP,
// acquireVsCodeApi(), the embedJson() JSON-into-<script> helper for the initial data, two-way
// postMessage. A TOML-authored code set is hand-authored/legacy and is opened READ-ONLY here (Save
// disabled) — `upsert` only ever writes CSV. After a save the Translation Tables tree refreshes and a
// Promote is offered (the same messagefoundry.promote command the connection editor reuses).
import * as vscode from "vscode";
import { configDir, runJson, workspaceDir } from "./cli";
import { STARTUP_BANNERS, openChannel, postToWebview } from "./webviewMessaging";
import { codeSetEditorScript } from "./codeSetEditorWebview";

// §2 DETAIL/GRID — the shape `show` emits and `upsert` consumes. Rows are an array-of-arrays (a grid
// is positional; headers carry the names once in `columns`), each inner row aligned to `columns`.
// #162 — a code set's declared unmapped-value policy (how a lookup miss resolves), authored via the
// `codesets/<name>.policy.toml` sidecar and SHOWN read-only in the grid. `kind:"none"` (or an absent
// policy) is the backward-compatible default: a miss returns the caller's `.get()` default / raises.
export interface Policy {
  kind: "none" | "default" | "passthrough" | "flag";
  default_value: string | null;
}

export interface Detail {
  name: string;
  format: "csv" | "toml";
  columns: string[];
  rows: string[][];
  policy?: Policy; // #162 — read-only in the grid (authored via the .policy.toml sidecar for v1)
}

// §2 SUMMARY — one per code set, from `codeset list` (used here only for the existing-name list so
// the grid can warn client-side about a duplicate name; the server is the authority).
interface Summary {
  name: string;
  format: "csv" | "toml";
  key: string;
  columns: string[];
  value_columns: string[];
  shape: "scalar" | "dict";
  entries: number;
  policy?: Policy; // #162
}

let panel: vscode.WebviewPanel | undefined;

export interface CodeSetEditorOpts {
  editName?: string; // edit an existing code set; omit to create a new one
  onSaved?: () => void;
}

/** Open the code-set grid editor. In edit mode, pre-fills via `codeset show`; a thrown error (e.g.
 *  "no such code set") is surfaced and the editor bails. For create-new, INITIAL is null. */
export async function openCodeSetEditor(
  context: vscode.ExtensionContext,
  opts: CodeSetEditorOpts,
): Promise<void> {
  const ws = workspaceDir();
  if (!ws) {
    void vscode.window.showInformationMessage("MessageFoundry: open a workspace folder first.");
    return;
  }

  let initial: Detail | null = null;
  if (opts.editName) {
    try {
      initial = await runJson<Detail>(
        ["codeset", "show", "--config", configDir(), "--name", opts.editName],
        ws,
      );
    } catch (e) {
      void vscode.window.showErrorMessage(
        `MessageFoundry: could not open code set "${opts.editName}" — ${String(e)}`,
      );
      return;
    }
  }

  // Existing names for the client-side duplicate-name warning (server stays the authority). A list
  // failure is non-fatal — the editor still opens, just without the warning.
  let existing: string[] = [];
  try {
    const summaries = await runJson<Summary[]>(["codeset", "list", "--config", configDir()], ws);
    existing = summaries.map((s) => s.name);
  } catch {
    existing = [];
  }

  if (panel) {
    panel.dispose(); // reopen fresh for the new target
  }
  panel = vscode.window.createWebviewPanel(
    "messagefoundry.codeSetEditor",
    initial ? `Edit ${initial.name}` : "New Translation Table",
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
    async (m: { command?: string; detail?: Detail; name?: string; to?: string }) => {
      if (m?.command === "save" && m.detail) {
        await save(m.detail, current, opts.onSaved, opts.editName);
      } else if (m?.command === "rename" && m.name && m.to) {
        await rename(m.name, m.to, current, opts.onSaved);
      } else if (m?.command === "delete" && m.name) {
        await remove(m.name, current, opts.onSaved);
      } else if (m?.command === "cancel") {
        current.dispose();
      }
    },
  );

  const readonly = initial?.format === "toml";
  current.webview.html = codeSetFormHtml(current.webview, initial, readonly, existing);
}

async function save(
  detail: Detail,
  current: vscode.WebviewPanel,
  onSaved?: () => void,
  editName?: string,
): Promise<void> {
  const ws = workspaceDir();
  if (!ws) {
    return;
  }
  // Create-intent (#240): pass `--name <editName>` on an EDIT of an existing stem so the CLI treats the
  // save as an overwrite of that code set; OMIT it when creating a new table so the server refuses a
  // name collision (`create=--name is None`) instead of silently overwriting an existing code set.
  const args = ["codeset", "upsert", "--config", configDir(), "--data", JSON.stringify(detail)];
  if (editName) {
    args.push("--name", editName);
  }
  try {
    await runJson(args, ws);
  } catch (e) {
    // Surface the validation/CLI error inline so the user can fix the grid (file was not changed).
    postToWebview(current.webview, { command: "error", message: String(e) });
    return;
  }
  current.dispose();
  onSaved?.();
  const pick = await vscode.window.showInformationMessage(
    `MessageFoundry: saved code set ${detail.name} to codesets/${detail.name}.csv.`,
    "Promote…",
  );
  if (pick === "Promote…") {
    void vscode.commands.executeCommand("messagefoundry.promote");
  }
}

async function rename(
  name: string,
  to: string,
  current: vscode.WebviewPanel,
  onSaved?: () => void,
): Promise<void> {
  const ws = workspaceDir();
  if (!ws) {
    return;
  }
  try {
    await runJson(["codeset", "rename", "--config", configDir(), "--name", name, "--to", to], ws);
  } catch (e) {
    postToWebview(current.webview, { command: "error", message: String(e) });
    return;
  }
  current.dispose();
  onSaved?.();
  void vscode.window.showInformationMessage(`MessageFoundry: renamed code set ${name} → ${to}.`);
}

async function remove(name: string, current: vscode.WebviewPanel, onSaved?: () => void): Promise<void> {
  const ws = workspaceDir();
  if (!ws) {
    return;
  }
  const confirm = await vscode.window.showWarningMessage(
    `Remove code set "${name}" (codesets/${name}.csv)?`,
    { modal: true },
    "Remove",
  );
  if (confirm !== "Remove") {
    return;
  }
  try {
    await runJson(["codeset", "remove", "--config", configDir(), "--name", name], ws);
  } catch (e) {
    postToWebview(current.webview, { command: "error", message: String(e) });
    return;
  }
  current.dispose();
  onSaved?.();
  void vscode.window.showInformationMessage(`MessageFoundry: removed code set ${name}.`);
}

export function codeSetFormHtml(
  webview: vscode.Webview,
  initial: Detail | null,
  readonly: boolean,
  existing: string[],
): string {
  const { nonce: n, token } = openChannel(webview);
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta http-equiv="Content-Security-Policy"
        content="default-src 'none'; style-src ${webview.cspSource} 'unsafe-inline'; script-src 'nonce-${n}';" />
  <style>
    body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); padding: 12px 16px; }
    h2 { font-size: 15px; margin: 0 0 4px; }
    .sub { font-size: 11px; color: var(--vscode-descriptionForeground); margin: 0 0 12px; max-width: 760px; }
    label { display: block; font-size: 12px; color: var(--vscode-descriptionForeground); margin: 10px 0 2px; }
    input { box-sizing: border-box; padding: 4px 6px; font-family: inherit; font-size: 13px;
      color: var(--vscode-input-foreground); background: var(--vscode-input-background);
      border: 1px solid var(--vscode-input-border, var(--vscode-panel-border)); border-radius: 2px; }
    input.name { width: 320px; font-family: var(--vscode-editor-font-family, monospace); }
    .ro-banner { display: none; margin: 8px 0; padding: 6px 10px; font-size: 12px; border-radius: 2px;
      color: var(--vscode-inputValidation-warningForeground, var(--vscode-foreground));
      background: var(--vscode-inputValidation-warningBackground, transparent);
      border: 1px solid var(--vscode-inputValidation-warningBorder, var(--vscode-panel-border)); }
    .grid-wrap { overflow-x: auto; margin-top: 8px; }
    table { border-collapse: collapse; font-size: 12px; }
    th, td { border: 1px solid var(--vscode-panel-border); padding: 0; }
    th { background: var(--vscode-editorWidget-background, transparent); }
    th.keyhead { position: sticky; left: 0; z-index: 2; }
    td.keycell { position: sticky; left: 0; z-index: 1; background: var(--vscode-editor-background); }
    .cellinput, .headinput { border: none; background: transparent; width: 140px; padding: 4px 6px;
      font-family: var(--vscode-editor-font-family, monospace); font-size: 12px; color: var(--vscode-foreground); }
    .headinput { font-weight: 600; width: 140px; }
    .cellinput:focus, .headinput:focus { outline: 1px solid var(--vscode-focusBorder); }
    /* LIVE highlight of duplicate / empty keys — the loader rejects a duplicate key and skips a blank one. */
    td.keycell.dup .cellinput { background: var(--vscode-inputValidation-errorBackground, rgba(255,0,0,0.18)); }
    td.keycell.empty .cellinput { background: var(--vscode-inputValidation-warningBackground, rgba(255,200,0,0.18)); }
    th .colbtn, .rowbtn { background: transparent; border: none; color: var(--vscode-errorForeground); cursor: pointer; padding: 0 4px; font-size: 12px; }
    th .colhead { display: flex; align-items: center; }
    .filterbar { margin-top: 8px; display: flex; align-items: center; gap: 8px; }
    input.search { width: 280px; }
    .searchcount { font-size: 11px; color: var(--vscode-descriptionForeground); }
    .toolbar { margin-top: 10px; display: flex; gap: 8px; flex-wrap: wrap; }
    .actions { margin-top: 18px; display: flex; gap: 8px; }
    button { font-family: inherit; color: var(--vscode-button-foreground); background: var(--vscode-button-background);
      border: none; padding: 6px 14px; cursor: pointer; border-radius: 2px; }
    button.secondary { color: var(--vscode-button-secondaryForeground); background: var(--vscode-button-secondaryBackground); }
    button.danger { background: transparent; color: var(--vscode-errorForeground); margin-left: auto; }
    button:hover { background: var(--vscode-button-hoverBackground); }
    button:disabled { opacity: 0.5; cursor: default; }
    .hint { font-size: 11px; color: var(--vscode-descriptionForeground); margin-top: 4px; }
    .policy { margin: 4px 0 0; padding: 6px 10px; font-size: 12px; border-radius: 2px;
      color: var(--vscode-foreground); background: var(--vscode-editorWidget-background, transparent);
      border: 1px solid var(--vscode-panel-border); }
    .policy code { font-family: var(--vscode-editor-font-family, monospace); }
    .warn { display: none; margin-top: 8px; font-size: 12px; color: var(--vscode-editorWarning-foreground, var(--vscode-descriptionForeground)); white-space: pre-wrap; }
    .error { display: none; margin-top: 12px; font-size: 12px; color: var(--vscode-errorForeground); white-space: pre-wrap; }
  </style>
</head>
<body>
  ${STARTUP_BANNERS}
  <h2 id="title">New Translation Table</h2>
  <p class="sub">A code set is read-only reference data in <code>codesets/&lt;name&gt;.csv</code>. The
     <b>first column is the lookup key</b>; every cell is a string. One value column → a scalar; two or
     more → a dict. The editor saves CSV (a <code>.toml</code> code set is hand-authored and opens read-only here).</p>

  <div id="ro-banner" class="ro-banner">This code set is authored in TOML and is <b>read-only</b> here.
     The grid editor saves CSV only — edit the <code>.toml</code> by hand.</div>

  <label for="name">Code-set name</label>
  <input id="name" class="name" placeholder="epic_diets" />
  <div class="hint">A bare file stem (no path, no <code>.csv</code>/<code>.toml</code> extension). Saved as <code>codesets/&lt;name&gt;.csv</code>.</div>

  <!-- #162 — the declared unmapped-value policy, SHOWN read-only (authored via the .policy.toml sidecar for v1). -->
  <label>Unmapped-value policy (on a lookup miss)</label>
  <div id="policy" class="policy">No policy declared — a miss returns the caller's <code>.get()</code> default (unchanged).</div>
  <div class="hint">Declared in <code>codesets/&lt;name&gt;.policy.toml</code> and applied by <code>code_set(name).translate(key)</code>. Read-only here.</div>

  <div class="filterbar">
    <input id="search" type="search" class="search" placeholder="Filter rows by key or value…" />
    <span id="searchcount" class="searchcount"></span>
  </div>

  <div class="grid-wrap">
    <table id="grid"><thead><tr id="headrow"></tr></thead><tbody id="body"></tbody></table>
  </div>

  <div class="toolbar">
    <button id="addRow" class="secondary">+ row</button>
    <button id="addCol" class="secondary">+ column</button>
  </div>

  <div id="warn" class="warn"></div>
  <div id="error" class="error"></div>

  <div class="actions">
    <button id="save">Save</button>
    <button id="cancel" class="secondary">Cancel</button>
    <button id="delete" class="danger" style="display:none;">Remove…</button>
  </div>

  <script nonce="${n}">${codeSetEditorScript(token, initial, readonly, existing)}
  </script>
</body>
</html>`;
}
