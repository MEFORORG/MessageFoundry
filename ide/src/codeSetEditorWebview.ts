// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
//
// The code-set editor webview's inline script, split out of codeSetEditor.ts so it can be loaded
// without `vscode`. codeSetEditor.ts builds the page and embeds this; the unit suite evaluates the
// SAME source in a jsdom page (webview-receivers.test.ts), so what the tests exercise is what
// ships.
import { SHAPE_HELPERS, WEBVIEW_GUARD_NOTE, embedJson, guardScript } from "./webviewMessaging";

/** The whole inline `<script>` body for one render, guard included. `token` is this render's
 *  channel token, minted by the caller with the nonce (webviewMessaging.ts). */
export function codeSetEditorScript(
  token: string,
  initial: unknown,
  readonly: boolean,
  existing: readonly string[],
): string {
  return `
    const vscode = acquireVsCodeApi();${guardScript(token)}${SHAPE_HELPERS}
    const INITIAL = ${embedJson(initial)};         // Detail | null
    const READONLY = ${embedJson(readonly)};       // true => TOML, view-only
    const EXISTING = ${embedJson(existing)};       // existing code-set names (client-side dup warning)
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
    // The one message the host posts (codeSetEditor.ts).
    const SHAPES = { error: (d) => mfStr(d.message) };
    ${WEBVIEW_GUARD_NOTE}
    window.addEventListener('message', (e) => {
      const d = mfTrusted(e);
      if (!d || !mfShapeOk(d, 'command', SHAPES, 'Code Set editor')) { return; }
      if (d.command === 'error') { errorEl.textContent = d.message; errorEl.style.display = ''; }
    });

    render();
  `;
}
