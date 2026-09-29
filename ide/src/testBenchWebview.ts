// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
//
// The Test Bench webview's inline script, split out of testBench.ts so it can be loaded without
// `vscode`. testBench.ts builds the page and embeds this; the unit suite evaluates the SAME source in
// a jsdom page (test-bench-webview.test.ts), so what the tests exercise is what ships.
import { WEBVIEW_GUARD_NOTE, guardScript } from "./webviewMessaging";

/**
 * The whole inline `<script>` body for one Test Bench render, guard included.
 *
 * `token` is this render's channel token, minted by the caller with the nonce (webviewMessaging.ts).
 */
export function testBenchScript(token: string): string {
  return `
    const vscode = acquireVsCodeApi();${guardScript(token)}
    const results = document.getElementById('results');
    const detail = document.getElementById('detail');
    const back = document.getElementById('back');
    const layout = document.getElementById('layout');
    const tracetoggle = document.getElementById('tracetoggle');
    let sbs = (vscode.getState() || {}).sbs || false; // remembered layout choice
    let traceMode = (vscode.getState() || {}).traceMode || 'coverage'; // 'coverage' | 'profile'
    let lastTrace = null; // the most recent trace detail, so the toggle can re-render it

    // Stringifies first, so a number reaching innerHTML goes through the same escape as a string.
    // Quotes too, matching the host-side esc(): a value must not be able to leave an attribute.
    function esc(s){
      return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
        .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
    }

    // PAYLOAD SHAPE (ASVS 3.5.5, BACKLOG #1123). mfTrusted() answers WHO sent a message; these answer
    // whether what it carries is the shape this panel renders. A message that fails is DISCARDED:
    // nothing renders and the view stays as it was. Escaping is a separate layer that bounds what a
    // well-shaped string can do once rendered; it is not what rejects a malformed message.
    function isStr(x){ return typeof x === 'string'; }
    function isNum(x){ return typeof x === 'number' && Number.isFinite(x); }
    function isCount(x){ return Number.isSafeInteger(x) && x >= 0; }
    function isBool(x){ return typeof x === 'boolean'; }
    function isObj(x){ return !!x && typeof x === 'object' && !Array.isArray(x); }
    function isArrOf(x, f){ return Array.isArray(x) && x.every(f); }
    const HEX_PAIR = /^[0-9a-f]{2}$/;

    function isDiffCell(c){
      return isObj(c) && isBool(c.seg) && isStr(c.status) && isStr(c.sep) &&
        isArrOf(c.fields, (f) => isObj(f) && isStr(f.t) && isBool(f.c));
    }
    function isCoverage(c){
      return isObj(c) && isStr(c.kind) && isStr(c.name) && isCount(c.executed) && isCount(c.executable) &&
        isNum(c.pct) && isBool(c.truncated) && isBool(c.sourceAvailable) &&
        isArrOf(c.lines, (l) => isObj(l) && isCount(l.line) && isCount(l.hits) && isStr(l.text) &&
          isBool(l.executable) && isBool(l.executed));
    }
    function isProfile(p){
      return isObj(p) && isStr(p.kind) && isStr(p.name) && isBool(p.hasTiming) && isNum(p.totalSeconds) &&
        isArrOf(p.lines, (l) => isObj(l) && isCount(l.line) && isCount(l.hits) && isNum(l.seconds) && isNum(l.pct));
    }
    function isFieldDifference(d){
      return isObj(d) && isStr(d.seg) && Number.isSafeInteger(d.index) && isStr(d.before) && isStr(d.after);
    }
    // One entry per type this panel renders. A type with no entry is not rendered, as before.
    const SHAPES = {
      detail: (m) => isStr(m.source) && isStr(m.to) && isObj(m.diff) &&
        isArrOf(m.diff.before, isDiffCell) && isArrOf(m.diff.after, isDiffCell),
      trace: (m) => isObj(m.detail) && isStr(m.detail.source) && isStr(m.detail.disposition) &&
        isBool(m.detail.hasTiming) && isNum(m.detail.totalSeconds) &&
        isArrOf(m.detail.invocations, (v) => isObj(v) && isCoverage(v.coverage) && isProfile(v.profile)),
      hex: (m) => isStr(m.source) && isObj(m.dump) && isBool(m.dump.truncated) &&
        isCount(m.dump.renderedBytes) && isCount(m.dump.totalBytes) &&
        // Bounded because it sizes a padding string; an unbounded one would throw inside repeat().
        isCount(m.dump.bytesPerRow) && m.dump.bytesPerRow >= 1 && m.dump.bytesPerRow <= 256 &&
        isArrOf(m.dump.lines, (l) => isObj(l) && isCount(l.offset) && isStr(l.ascii) &&
          isArrOf(l.hex, (h) => isStr(h) && HEX_PAIR.test(h)) && l.hex.length <= m.dump.bytesPerRow),
      collections: (m) => isArrOf(m.items, (c) => isObj(c) && isStr(c.name) && isCount(c.cases)),
      collectionRun: (m) => isStr(m.name) && isCount(m.passed) && isCount(m.total) &&
        isArrOf(m.results, (r) => isObj(r) && isStr(r.name) && isBool(r.pass) && isStr(r.disposition) &&
          (r.error === null || isStr(r.error)) &&
          isArrOf(r.deliveries, (d) => isObj(d) && isStr(d.to) && isStr(d.status) &&
            isArrOf(d.differences, isFieldDifference))),
    };
    function shapeOk(m){
      const check = isStr(m.type) && Object.prototype.hasOwnProperty.call(SHAPES, m.type) ? SHAPES[m.type] : null;
      return !!check && check(m);
    }

    // Render one side of the HL7-aware diff. The cells are aligned so before[i] lines up with
    // after[i]: a gap cell (seg=false) holds the place opposite an inserted/deleted segment, and
    // each segment's changed fields are highlighted inline (side picks red 'del' vs green 'ins').
    function pane(label, cells, side){
      const span = side === 'before' ? 'del' : 'ins';
      const html = cells.map((cell) => {
        if (!cell.seg) return '<div class="ln gap">&nbsp;</div>';
        let cls = 'ln';
        if (cell.status === 'added') cls += ' ln-ins';
        else if (cell.status === 'removed') cls += ' ln-del';
        const inner = cell.fields.map((f) =>
          f.c ? '<span class="' + span + '">' + (esc(f.t) || '&nbsp;') + '</span>' : esc(f.t)
        ).join(esc(cell.sep));
        return '<div class="' + cls + '">' + (inner || '&nbsp;') + '</div>';
      }).join('');
      return '<div class="pane"><div class="lbl">' + esc(label) + '</div><pre>' + html + '</pre></div>';
    }

    function layoutLabel(){ layout.textContent = sbs ? 'Top / bottom' : 'Side by side'; }
    function traceToggleLabel(){ tracetoggle.textContent = traceMode === 'coverage' ? 'Show Profiling' : 'Show Coverage'; }

    // Human-readable time from seconds (traced wall time; includes tracer overhead, so comparative).
    function fmtTime(s){
      if (!(s > 0)) return '0';
      if (s < 1e-6) return (s * 1e9).toFixed(0) + ' ns';
      if (s < 1e-3) return (s * 1e6).toFixed(1) + ' µs';
      if (s < 1) return (s * 1e3).toFixed(2) + ' ms';
      return s.toFixed(3) + ' s';
    }
    function pct(p){ return (p || 0).toFixed(p >= 10 ? 0 : 1) + '%'; }

    // COVERAGE: source lines of one @router/@handler, executed (green) vs not (red) vs context (dim).
    function coverageInv(cov){
      const head = '<h4><span class="kind">' + esc(cov.kind) + '</span> ' + esc(cov.name) +
        ' <span class="meta">' + esc(cov.executed) + '/' + esc(cov.executable) + ' lines' +
        (cov.executable ? ' &middot; ' + esc(pct(cov.pct)) : '') + '</span></h4>';
      const notes =
        (cov.truncated ? '<div class="note">Trace hit its event cap — coverage may under-report.</div>' : '') +
        (cov.sourceAvailable ? '' : '<div class="note">Source file unavailable — showing executed lines only.</div>');
      const rows = cov.lines.map((l) => {
        let cls = 'row non';
        if (l.executable) cls = l.executed ? 'row hit' : 'row miss';
        const hits = l.hits > 1 ? ' <span class="hits">&times;' + esc(l.hits) + '</span>' : '';
        const src = cov.sourceAvailable ? (esc(l.text) || '&nbsp;') : ('line ' + esc(l.line) + ' executed');
        return '<div class="' + cls + '"><span class="g">' + esc(l.line) + hits + '</span><span class="src">' + src + '</span></div>';
      }).join('');
      return '<div class="inv">' + head + notes + '<pre class="cov">' + rows + '</pre></div>';
    }

    // PROFILING: per-invocation total + a per-line time/%/bar table (hottest first).
    function profileInv(prof){
      const head = '<h4><span class="kind">' + esc(prof.kind) + '</span> ' + esc(prof.name) +
        ' <span class="meta">' + esc(fmtTime(prof.totalSeconds)) + ' total</span></h4>';
      if (!prof.hasTiming) {
        return '<div class="inv">' + head + '<div class="note">This trace carried no timing.</div></div>';
      }
      if (!prof.lines.length) {
        return '<div class="inv">' + head + '<div class="note">No lines executed.</div></div>';
      }
      const body = prof.lines.map((l) => {
        const bar = '<span class="pbartrack"><span class="pbar" style="width:' + esc(Math.max(0, Math.min(100, l.pct)).toFixed(1)) + '%"></span></span>';
        return '<tr><td>' + esc(l.line) + '</td><td>' + esc(l.hits) + '</td><td>' + esc(fmtTime(l.seconds)) +
          '</td><td>' + esc(pct(l.pct)) + '</td><td>' + bar + '</td></tr>';
      }).join('');
      return '<div class="inv">' + head +
        '<table class="prof"><thead><tr><th>Line</th><th>Hits</th><th>Time</th><th>%</th><th>Share</th></tr></thead>' +
        '<tbody>' + body + '</tbody></table></div>';
    }

    function renderTrace(){
      if (!lastTrace) return;
      const t = lastTrace;
      let inner;
      if (traceMode === 'profile') {
        const summary = t.hasTiming
          ? '<div class="note">Total traced time ' + esc(fmtTime(t.totalSeconds)) + ' &middot; timings include tracer overhead (comparative, not a benchmark).</div>'
          : '<div class="note">This trace carried no per-line timing.</div>';
        inner = summary + t.invocations.map((v) => profileInv(v.profile)).join('');
      } else {
        inner = '<div class="note">Green = executed &middot; red = not executed &middot; dim = non-executable (def / comment / blank).</div>' +
          t.invocations.map((v) => coverageInv(v.coverage)).join('');
      }
      const label = traceMode === 'profile' ? 'Profiling' : 'Coverage';
      detail.innerHTML = '<h3>' + label + ' — ' + esc(t.source) +
        ' <span class="meta">(' + esc(t.disposition) + ')</span></h3>' +
        (t.invocations.length ? inner : '<div class="note">No Router/Handler ran for this message.</div>');
    }

    // HEX (#84): render the posted UTF-8 byte dump — offset gutter, space-joined hex pairs (padded so
    // the ASCII gutter stays aligned on a short final row), then the printable-ASCII gutter.
    function renderHex(source, dump){
      const per = dump.bytesPerRow;
      const rows = dump.lines.map((l) => {
        const off = l.offset.toString(16).padStart(8, '0');
        const pairs = l.hex.join(' ');
        const pad = ' '.repeat(Math.max(0, (per - l.hex.length) * 3));
        return '<div class="row"><span class="off">' + esc(off) + '</span>' +
          '<span class="bytes">' + esc(pairs) + pad + '</span>' +
          '<span class="txt">' + esc(l.ascii) + '</span></div>';
      }).join('');
      const note = dump.truncated
        ? '<div class="note">Showing the first ' + esc(dump.renderedBytes) + ' of ' + esc(dump.totalBytes) + ' bytes (render capped).</div>'
        : '<div class="note">' + esc(dump.totalBytes) + ' bytes.</div>';
      const subtitle = '<div class="note">UTF-8 bytes of the message as the dry-run decoded it (not the original wire bytes).</div>';
      detail.innerHTML = '<h3>Hex — ' + esc(source) + '</h3>' + subtitle + note +
        (dump.lines.length ? '<pre class="hex">' + rows + '</pre>' : '<div class="note">Empty body.</div>');
    }

    // COLLECTIONS (#168): the saved-collection list with Run / Delete, plus a machine-local PHI notice.
    function showDetailView(){
      results.style.display = 'none'; detail.style.display = 'block';
      back.hidden = false; layout.hidden = true; tracetoggle.hidden = true; lastTrace = null;
    }
    let collNames = []; // index to collection name; the DOM keys on the index, never the raw name (a name
                        // is user text, so it stays out of attributes even though esc() now covers quotes).
    function renderCollections(items){
      collNames = items.map((c) => c.name);
      const notice = '<div class="phi">Cases (input + expected output bodies) are stored machine-locally in this workspace only ' +
        '(never synced, never committed). Use synthetic, de-identified messages — not real PHI.</div>';
      const list = items.length
        ? items.map((c, i) =>
            '<div class="coll"><span class="nm">' + esc(c.name) + '</span>' +
            '<span class="ct">' + esc(c.cases) + ' case' + (c.cases === 1 ? '' : 's') + '</span>' +
            '<button data-coll-run="' + i + '">Run</button>' +
            '<button data-coll-del="' + i + '">Delete</button></div>'
          ).join('')
        : '<div class="note">No saved collections yet. Load a message set, then <b>Save as Collection…</b>.</div>';
      detail.innerHTML = '<h3>Regression collections</h3>' + notice + list;
      showDetailView();
      for (const b of detail.querySelectorAll('button[data-coll-run]')) {
        b.addEventListener('click', () => vscode.postMessage({ command: 'runCollection', name: collNames[Number(b.dataset.collRun)] }));
      }
      for (const b of detail.querySelectorAll('button[data-coll-del]')) {
        b.addEventListener('click', () => vscode.postMessage({ command: 'deleteCollection', name: collNames[Number(b.dataset.collDel)] }));
      }
    }

    function diffLine(d){
      if (d.index < 0) {
        // whole added/removed segment
        return d.before
          ? '<div><code>' + esc(d.seg) + '</code> removed: <span class="del">' + esc(d.before) + '</span></div>'
          : '<div><code>' + esc(d.seg) + '</code> added: <span class="ins">' + esc(d.after) + '</span></div>';
      }
      return '<div><code>' + esc(d.seg) + '[' + esc(d.index) + ']</code>: ' +
        '<span class="del">' + (esc(d.before) || '∅') + '</span> &rarr; ' +
        '<span class="ins">' + (esc(d.after) || '∅') + '</span></div>';
    }
    function renderCollectionRun(msg){
      const cases = msg.results.map((r) => {
        const badge = r.pass ? '<span class="badge pass">PASS</span>' : '<span class="badge fail">FAIL</span>';
        const failNotes = r.pass ? '' : r.deliveries.map((d) => {
          if (d.status === 'missing') return '<div class="diffs">Expected delivery to <code>' + esc(d.to) + '</code> was not produced.</div>';
          if (d.status === 'unexpected') return '<div class="diffs">Unexpected delivery to <code>' + esc(d.to) + '</code>.</div>';
          if (d.status === 'mismatch') return '<div class="diffs">To <code>' + esc(d.to) + '</code>:' + d.differences.map(diffLine).join('') + '</div>';
          return '';
        }).join('');
        const err = r.error ? '<div class="diffs">' + esc(r.error) + '</div>' : '';
        return '<div class="case"><div class="hd">' + badge + '<span class="cn">' + esc(r.name) +
          '</span><span class="note">' + esc(r.disposition) + '</span></div>' + err + failNotes + '</div>';
      }).join('');
      const allPass = msg.passed === msg.total;
      const summary = '<span class="badge ' + (allPass ? 'pass' : 'fail') + '">' + esc(msg.passed) + ' / ' + esc(msg.total) + ' passed</span>';
      detail.innerHTML = '<h3>Run — ' + esc(msg.name) + ' &nbsp; ' + summary + '</h3>' + cases;
      showDetailView();
    }

    function saveState(){ vscode.setState({ sbs, traceMode }); }

    document.getElementById('load').addEventListener('click', () => vscode.postMessage({ command: 'load' }));
    document.getElementById('collections').addEventListener('click', () => vscode.postMessage({ command: 'listCollections' }));
    document.getElementById('savecoll').addEventListener('click', () => vscode.postMessage({ command: 'saveCollection' }));
    back.addEventListener('click', () => {
      detail.style.display='none'; results.style.display=''; lastTrace=null;
      back.hidden=true; layout.hidden=true; tracetoggle.hidden=true;
    });
    layout.addEventListener('click', () => {
      sbs = !sbs; saveState(); layoutLabel();
      const p = document.querySelector('.panes'); if (p) p.classList.toggle('sbs', sbs);
    });
    tracetoggle.addEventListener('click', () => {
      traceMode = traceMode === 'coverage' ? 'profile' : 'coverage'; saveState();
      traceToggleLabel(); renderTrace();
    });
    for (const b of document.querySelectorAll('button[data-act]')) {
      b.addEventListener('click', () => vscode.postMessage({ command: b.dataset.act, index: Number(b.dataset.i) }));
    }

    ${WEBVIEW_GUARD_NOTE}
    window.addEventListener('message', (ev) => {
      const m = mfTrusted(ev);
      if (!m) return;
      if (!shapeOk(m)) {
        // Discarded, not render-escaped: see PAYLOAD SHAPE above. Said in the webview console so a
        // host and page that drift apart read as a named discard, not a button that does nothing.
        console.warn('MessageFoundry Test Bench: discarded a malformed "' + String(m.type) + '" message');
        return;
      }
      if (m.type === 'detail') {
        const diff = m.diff;
        detail.innerHTML =
          '<h3>' + esc(m.source) + ' &rarr; ' + esc(m.to) + '</h3>' +
          '<div class="panes' + (sbs ? ' sbs' : '') + '">' +
            pane('Before (received)', diff.before, 'before') +
            pane('After (would send to ' + m.to + ')', diff.after, 'after') +
          '</div>';
        lastTrace = null;
        results.style.display = 'none';
        detail.style.display = 'block';
        back.hidden = false;
        layout.hidden = false;
        tracetoggle.hidden = true;
        layoutLabel();
      } else if (m.type === 'trace') {
        lastTrace = m.detail;
        renderTrace();
        results.style.display = 'none';
        detail.style.display = 'block';
        back.hidden = false;
        layout.hidden = true;
        tracetoggle.hidden = false;
        traceToggleLabel();
      } else if (m.type === 'hex') {
        renderHex(m.source, m.dump);
        lastTrace = null;
        results.style.display = 'none';
        detail.style.display = 'block';
        back.hidden = false;
        layout.hidden = true;
        tracetoggle.hidden = true;
      } else if (m.type === 'collections') {
        renderCollections(m.items);
      } else if (m.type === 'collectionRun') {
        renderCollectionRun(m);
      }
    });
  `;
}
