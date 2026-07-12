// Code-set (translation table) grid editor — a webview that creates/edits a codesets/<name>.csv by
// shelling the `messagefoundry codeset show|upsert|rename|remove` CLI (which validates + writes the
// CSV, then re-loads it as the post-write authority). A code set is read-only reference data: the
// first column is the lookup key, every cell is a string (CSV-first). This grid is exactly that —
// rows×columns of strings, key column pinned first.
//
// Mirrors connectionEditor.ts: a single WebviewPanel, scripts enabled, a nonce'd CSP,
// acquireVsCodeApi(), the embed() JSON-into-<script> helper for the initial data, two-way
// postMessage. A TOML-authored code set is hand-authored/legacy and is opened READ-ONLY here (Save
// disabled) — `upsert` only ever writes CSV. After a save the Translation Tables tree refreshes and a
// Promote is offered (the same messagefoundry.promote command the connection editor reuses).
import * as vscode from "vscode";
import { configDir, runJson, workspaceDir } from "./cli";

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
        await save(m.detail, current, opts.onSaved);
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

async function save(detail: Detail, current: vscode.WebviewPanel, onSaved?: () => void): Promise<void> {
  const ws = workspaceDir();
  if (!ws) {
    return;
  }
  try {
    await runJson(["codeset", "upsert", "--config", configDir(), "--data", JSON.stringify(detail)], ws);
  } catch (e) {
    // Surface the validation/CLI error inline so the user can fix the grid (file was not changed).
    current.webview.postMessage({ command: "error", message: String(e) });
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
    current.webview.postMessage({ command: "error", message: String(e) });
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
    current.webview.postMessage({ command: "error", message: String(e) });
    return;
  }
  current.dispose();
  onSaved?.();
  void vscode.window.showInformationMessage(`MessageFoundry: removed code set ${name}.`);
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

export function codeSetFormHtml(
  webview: vscode.Webview,
  initial: Detail | null,
  readonly: boolean,
  existing: string[],
): string {
  const n = nonce();
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

  <script nonce="${n}">
    const vscode = acquireVsCodeApi();
    const INITIAL = ${embed(initial)};         // Detail | null
    const READONLY = ${embed(readonly)};       // true => TOML, view-only
    const EXISTING = ${embed(existing)};       // existing code-set names (client-side dup warning)
    const $ = (id) => document.getElementById(id);
    const errorEl = $('error');
    const warnEl = $('warn');

    // ----- grid model: columns (header strings) + rows (string[][], aligned to columns). -----
    let columns = ['key', 'value'];
    let rows = [['', '']];
    const originalName = INITIAL ? INITIAL.name : null;

    // #162 — SHOW the declared unmapped-value policy read-only (authored via the .policy.toml sidecar).
    function renderPolicy(policy) {
      const el = $('policy');
      if (!el) return;
      const kind = policy && policy.kind ? policy.kind : 'none';
      if (kind === 'default') {
        const dv = policy && policy.default_value != null ? String(policy.default_value) : '';
        el.innerHTML = 'On a miss, return the configured default: <code></code>';
        el.querySelector('code').textContent = dv;
      } else if (kind === 'passthrough') {
        el.textContent = 'On a miss, return the original key unchanged (passthrough).';
      } else if (kind === 'flag') {
        el.textContent = 'On a miss, return a flag-for-review outcome the handler/operator can see.';
      } else {
        el.innerHTML = 'No policy declared — a miss returns the caller\\'s <code>.get()</code> default (unchanged).';
      }
    }

    if (INITIAL) {
      $('title').textContent = 'Edit ' + INITIAL.name;
      $('name').value = INITIAL.name;
      renderPolicy(INITIAL.policy);
      // Renaming is a distinct CLI op; we keep the name field editable but a name change on Save is
      // treated as upsert-of-new unless the row action's rename is used. To avoid an accidental
      // duplicate, lock the name in edit mode (rename uses the tree's Rename action).
      $('name').disabled = true;
      columns = Array.isArray(INITIAL.columns) && INITIAL.columns.length >= 1 ? INITIAL.columns.slice() : ['key', 'value'];
      rows = Array.isArray(INITIAL.rows) ? INITIAL.rows.map((r) => columns.map((_, i) => (r[i] == null ? '' : String(r[i])))) : [];
      $('delete').style.display = '';
    }
    if (rows.length === 0) {
      rows = [columns.map(() => '')];
    }

    if (READONLY) {
      $('ro-banner').style.display = '';
      $('save').disabled = true;
      $('addRow').disabled = true;
      $('addCol').disabled = true;
    }

    // ----- read the current grid back out of the DOM into the model (so edits aren't lost on re-render). -----
    function syncFromDom() {
      const headInputs = $('headrow').querySelectorAll('.headinput');
      columns = Array.from(headInputs).map((el) => el.value);
      const bodyRows = $('body').querySelectorAll('tr');
      rows = Array.from(bodyRows).map((tr) => Array.from(tr.querySelectorAll('.cellinput')).map((el) => el.value));
    }

    function render() {
      // header
      const headrow = $('headrow');
      headrow.innerHTML = '';
      columns.forEach((col, c) => {
        const th = document.createElement('th');
        if (c === 0) { th.className = 'keyhead'; }
        const wrap = document.createElement('div'); wrap.className = 'colhead';
        const inp = document.createElement('input'); inp.type = 'text'; inp.className = 'headinput';
        inp.value = col == null ? '' : String(col);
        inp.placeholder = c === 0 ? 'key' : ('value' + (columns.length > 2 ? c : ''));
        inp.disabled = READONLY;
        inp.addEventListener('input', () => { syncFromDom(); recompute(); });
        wrap.appendChild(inp);
        // The key column is pinned and cannot be removed; value columns get a remove button.
        if (c > 0 && !READONLY) {
          const rm = document.createElement('button'); rm.className = 'colbtn'; rm.title = 'remove column'; rm.textContent = '×';
          rm.addEventListener('click', () => { syncFromDom(); removeColumn(c); });
          wrap.appendChild(rm);
        }
        th.appendChild(wrap);
        headrow.appendChild(th);
      });
      // trailing header cell for the row-remove buttons
      const thx = document.createElement('th'); thx.textContent = ''; headrow.appendChild(thx);

      // body
      const body = $('body');
      body.innerHTML = '';
      rows.forEach((row, r) => {
        const tr = document.createElement('tr');
        columns.forEach((_, c) => {
          const td = document.createElement('td');
          if (c === 0) { td.className = 'keycell'; }
          const inp = document.createElement('input'); inp.type = 'text'; inp.className = 'cellinput';
          inp.value = row[c] == null ? '' : String(row[c]);
          inp.disabled = READONLY;
          inp.addEventListener('input', () => { syncFromDom(); recompute(); });
          td.appendChild(inp);
          tr.appendChild(td);
        });
        const tdx = document.createElement('td');
        if (!READONLY) {
          const rm = document.createElement('button'); rm.className = 'rowbtn'; rm.title = 'remove row'; rm.textContent = '×';
          rm.addEventListener('click', () => { syncFromDom(); removeRow(r); });
          tdx.appendChild(rm);
        }
        tr.appendChild(tdx);
        body.appendChild(tr);
      });
      recompute();
      filterRows();
    }

    // LIVE highlight: a duplicate non-empty key is a load error; a blank key is dropped on write.
    function recompute() {
      const keyCells = $('body').querySelectorAll('td.keycell');
      const seen = new Map();
      let dupCount = 0, emptyCount = 0;
      keyCells.forEach((td, i) => {
        td.classList.remove('dup', 'empty');
        const key = (rows[i] && rows[i][0] != null) ? String(rows[i][0]) : '';
        if (key === '') { td.classList.add('empty'); emptyCount++; return; }
        if (seen.has(key)) { td.classList.add('dup'); dupCount++; const first = seen.get(key); keyCells[first].classList.add('dup'); }
        else { seen.set(key, i); }
      });
      const msgs = [];
      if (dupCount) { msgs.push('Duplicate key(s) highlighted — keys must be unique (the loader rejects duplicates).'); }
      if (emptyCount) { msgs.push(emptyCount + ' row(s) have a blank key and will be dropped on save.'); }
      // client-side duplicate-name warning (server is the authority)
      const nm = $('name').value.trim();
      if (nm && originalName !== nm && EXISTING.indexOf(nm) !== -1) {
        msgs.push('A code set named "' + nm + '" already exists — saving will overwrite it.');
      }
      if (msgs.length) { warnEl.textContent = msgs.join('\\n'); warnEl.style.display = ''; }
      else { warnEl.style.display = 'none'; }
    }

    // In-grid row filter (#161): display-only — a non-matching row is hidden but its inputs stay in
    // the DOM, so syncFromDom()/Save still capture every row. Re-applied at the end of render() so it
    // survives add/remove-row and add/remove-column. Case-insensitive substring over all cells.
    function filterRows() {
      const q = ($('search').value || '').trim().toLowerCase();
      const bodyRows = $('body').querySelectorAll('tr');
      let shown = 0;
      bodyRows.forEach((tr) => {
        const cells = Array.from(tr.querySelectorAll('.cellinput'));
        const match = !q || cells.some((el) => String(el.value).toLowerCase().includes(q));
        tr.style.display = match ? '' : 'none';
        if (match) shown++;
      });
      $('searchcount').textContent = q ? (shown + ' / ' + bodyRows.length + ' rows') : '';
    }

    function addRow() { syncFromDom(); rows.push(columns.map(() => '')); render(); }
    function addColumn() { syncFromDom(); columns.push('value' + columns.length); rows = rows.map((r) => { const c = r.slice(); c.push(''); return c; }); render(); }
    function removeRow(r) { rows.splice(r, 1); if (rows.length === 0) rows = [columns.map(() => '')]; render(); }
    function removeColumn(c) {
      if (c <= 0) return;                       // the key column is pinned
      if (columns.length <= 2) { errorEl.textContent = 'A code set needs a key column plus at least one value column.'; errorEl.style.display = ''; return; }
      errorEl.style.display = 'none';
      columns.splice(c, 1);
      rows = rows.map((r) => { const x = r.slice(); x.splice(c, 1); return x; });
      render();
    }

    $('addRow').addEventListener('click', addRow);
    $('addCol').addEventListener('click', addColumn);
    $('name').addEventListener('input', recompute);
    $('search').addEventListener('input', filterRows);

    function buildDetail() {
      syncFromDom();
      return { name: $('name').value.trim(), format: 'csv', columns: columns, rows: rows };
    }

    function clientValidate(detail) {
      const need = [];
      if (!detail.name) { errorEl.textContent = 'A code-set name is required.'; errorEl.style.display = ''; return false; }
      if (detail.columns.length < 2) { errorEl.textContent = 'A code set needs a key column plus at least one value column.'; errorEl.style.display = ''; return false; }
      if (detail.columns.some((h) => String(h).trim() === '')) { errorEl.textContent = 'Every column needs a non-empty header.'; errorEl.style.display = ''; return false; }
      const seen = new Set();
      for (const h of detail.columns) { if (seen.has(h)) { errorEl.textContent = 'Duplicate column header "' + h + '" — headers must be unique.'; errorEl.style.display = ''; return false; } seen.add(h); }
      // a duplicate non-empty key is a hard error (mirrors the loader)
      const keys = new Set();
      for (const row of detail.rows) { const k = row[0] != null ? String(row[0]) : ''; if (k === '') continue; if (keys.has(k)) { errorEl.textContent = 'Duplicate key "' + k + '" — keys must be unique.'; errorEl.style.display = ''; return false; } keys.add(k); }
      errorEl.style.display = 'none';
      return true;
    }

    $('save').addEventListener('click', () => {
      if (READONLY) return;
      const detail = buildDetail();
      if (!clientValidate(detail)) return;
      vscode.postMessage({ command: 'save', detail: detail });
    });
    $('cancel').addEventListener('click', () => vscode.postMessage({ command: 'cancel' }));
    $('delete').addEventListener('click', () => { if (originalName) vscode.postMessage({ command: 'delete', name: originalName }); });

    // CLI/validation errors arrive here and stay inline so the grid is still editable (file unchanged).
    window.addEventListener('message', (e) => {
      if (e.data && e.data.command === 'error') { errorEl.textContent = e.data.message; errorEl.style.display = ''; }
    });

    render();
  </script>
</body>
</html>`;
}
