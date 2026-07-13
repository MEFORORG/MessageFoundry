    // acquireVsCodeApi() may be called only ONCE per webview context. With retainContextWhenHidden the
    // script can re-run against a RETAINED window (after a hide/show or an html reassignment); a SECOND
    // call throws "an instance of the VS Code API has already been acquired" — and it would die HERE, at
    // the very first statement, BEFORE the error handler below is even registered, silently killing the
    // whole toolbar (Add/Copy/Cut/Paste never enable, rows don't select). Cache it on window so a re-run
    // reuses the same instance instead of re-acquiring. (This is the standard retain-context webview fix.)
    const vscode = window.__mfStepsVscode || (window.__mfStepsVscode = acquireVsCodeApi());
    // Provider-side handshake: tell the provider the script actually STARTED. If the provider never hears
    // this, it knows the script failed to initialize (blocked / threw at load) and surfaces that itself.
    try { vscode.postMessage({ command: 'stepsDiag', level: 'ping', text: 'alive' }); } catch (_) {}

    // Resilience + diagnostics: surface ANY uncaught script error to the provider (a toast) instead of
    // leaving the toolbar silently dead (a runtime throw before the enablement wiring would disable Add /
    // Copy / Cut / Paste with no clue why). Registered first so it catches throws in all setup below.
    window.addEventListener('error', (e) => {
      try {
        vscode.postMessage({ command: 'stepsDiag', level: 'error',
          text: 'script error: ' + (e && e.message) + ' @ line ' + (e && e.lineno) + ':' + (e && e.colno) });
      } catch (_) { /* nothing we can do */ }
    });

    // Ctrl/Cmd+Z → undo, Ctrl/Cmd+Shift+Z or Ctrl+Y → redo. The webview swallows these keys, so they never
    // reach the document's edit stack on their own; route them to the SAME undo/redo path the toolbar
    // buttons use (the provider runs vscode.commands 'undo'/'redo' behind the edit guard, then re-projects).
    // While a param INPUT is focused we defer to the field's own text undo instead of hijacking it.
    document.addEventListener('keydown', (ev) => {
      if (!(ev.ctrlKey || ev.metaKey)) { return; }
      const ae = document.activeElement;
      if (ae && (ae.tagName === 'INPUT' || ae.tagName === 'TEXTAREA' || ae.tagName === 'SELECT')) { return; }
      const key = (ev.key || '').toLowerCase();
      if (key === 'z' && !ev.shiftKey) { ev.preventDefault(); vscode.postMessage({ command: 'undo' }); }
      else if ((key === 'z' && ev.shiftKey) || key === 'y') { ev.preventDefault(); vscode.postMessage({ command: 'redo' }); }
      else if (key === 'c' || key === 'x' || key === 'v') {
        // Steps clipboard on the SELECTED row — but DEFER to native when a real text selection exists (copy
        // the selected text, not the row), mirroring the focused-input bail above.
        if (window.getSelection && String(window.getSelection())) { return; }
        ev.preventDefault();
        if (key === 'c') { copySelected(); } else if (key === 'x') { cutSelected(); } else { pasteSelected(); }
      }
    });

    // ---- ↑/↓ = a stepwise cross-suite drag ("walk into blocks") — mirror of stepsModel.walkMove ---------
    // The inline script can't import across the webview boundary, so these mirror the pure source-of-truth in
    // stepsModel.ts (unit-tested there). stepsCtxRows() reads the current DOM rows; buildDropSlots enumerates
    // every insertion slot in visible (DFS) order (the same slots resolveDrop reaches); walkMove finds the
    // block's current gap and returns the ADJACENT slot — a DropResolution that maps 1:1 to a drag-to-target
    // moveTo, so an arrow move rides the verified cross-suite engine path.
    function stepsCtxRows() {
      return Array.from(document.querySelectorAll('li.row')).map((el) => ({
        lineStart: Number(el.dataset.lineStart),
        lineEnd: Number(el.dataset.lineEnd),
        nesting: Number(el.dataset.nesting),
        suite: el.dataset.suite,
        kind: el.dataset.kind,
        control: el.dataset.control || undefined,
        expectSrc: el.dataset.expectSrc,
        draggable: el.getAttribute('draggable') === 'true',
        isControlHeader: el.dataset.kind === 'control' && el.getAttribute('draggable') === 'true',
      }));
    }
    // ---- Steps block copy/cut/paste mirrors (source of truth: stepsModel.blockExtent / captureBlock) ----
    // The inline script can't import across the webview boundary, so these mirror the pure, unit-tested model
    // helpers. blockExtent returns the [mi..mj] span of the movable block whose header is blockStartLine;
    // captureBlock joins those rows' projected source into the LF clipboard block.
    function blockExtent(rws, blockStartLine) {
      const mi = rws.findIndex((r) => r.lineStart === blockStartLine);
      if (mi < 0) { return null; }
      const m = rws[mi];
      if (!m.draggable) { return null; }
      let mj = mi;
      if (m.isControlHeader) {
        for (let i = mi + 1; i < rws.length; i++) {
          const r = rws[i];
          const c = r.nesting === m.nesting && (r.control === 'elif' || r.control === 'else');
          if (r.nesting > m.nesting || c) { mj = i; } else { break; }
        }
      }
      return { startIndex: mi, endIndex: mj };
    }
    function captureBlock(rws, blockStartLine) {
      const ext = blockExtent(rws, blockStartLine);
      if (!ext) { return null; }
      const start = rws[ext.startIndex];
      if (start.kind === 'code') { return null; } // a Code step is read-only — never copied
      const parts = [];
      for (let i = ext.startIndex; i <= ext.endIndex; i++) { parts.push(rws[i].expectSrc); }
      return {
        source: parts.join('\n'),
        nesting: start.nesting,
        kind: start.kind,
        control: start.control,
        lineStart: start.lineStart,
        lineEnd: rws[ext.endIndex].lineEnd,
        lineCount: ext.endIndex - ext.startIndex + 1,
      };
    }
    function buildDropSlots(rws) {
      const bySuite = new Map();
      for (const r of rws) { const l = bySuite.get(r.suite); if (l) { l.push(r); } else { bySuite.set(r.suite, [r]); } }
      const root = rws.find((r) => r.nesting === 0);
      const slots = [];
      if (!root) { return slots; }
      const cont = (r) => r.control === 'elif' || r.control === 'else';
      const emit = (suiteId) => {
        const ch = bySuite.get(suiteId) || [];
        let first = false;
        for (let i = 0; i < ch.length; i++) {
          const R = ch[i];
          if (cont(R)) { continue; }
          if (!first) { slots.push({ anchorLineStart: R.lineStart, anchorLineEnd: R.lineEnd, toPosition: 'before', toSuite: suiteId, landingDepth: R.nesting }); first = true; }
          if (R.isControlHeader) {
            emit(String(R.lineStart));
            for (let j = i + 1; j < ch.length && cont(ch[j]); j++) { emit(String(ch[j].lineStart)); }
            slots.push({ anchorLineStart: R.lineStart, anchorLineEnd: R.lineEnd, toPosition: 'after', toSuite: suiteId, landingDepth: R.nesting });
          } else if (R.kind !== 'send') {
            slots.push({ anchorLineStart: R.lineStart, anchorLineEnd: R.lineEnd, toPosition: 'after', toSuite: suiteId, landingDepth: R.nesting });
          }
        }
      };
      emit(root.suite);
      return slots;
    }
    function walkMove(rws, blockStartLine, direction) {
      const mi = rws.findIndex((r) => r.lineStart === blockStartLine);
      if (mi < 0) { return null; }
      const m = rws[mi];
      if (!m.draggable || !m.suite) { return null; }
      let mj = mi;
      if (m.isControlHeader) {
        for (let i = mi + 1; i < rws.length; i++) {
          const r = rws[i];
          const c = r.nesting === m.nesting && (r.control === 'elif' || r.control === 'else');
          if (r.nesting > m.nesting || c) { mj = i; } else { break; }
        }
      }
      const sibs = rws.filter((r) => r.suite === m.suite && !(r.control === 'elif' || r.control === 'else'));
      if (sibs.length < 2) { return null; }
      const k = sibs.findIndex((r) => r.lineStart === m.lineStart);
      const slots = buildDropSlots(rws.filter((_r, idx) => idx < mi || idx > mj));
      const cur = k > 0
        ? { toSuite: m.suite, toPosition: 'after', anchorLineStart: sibs[k - 1].lineStart }
        : { toSuite: m.suite, toPosition: 'before', anchorLineStart: sibs[1].lineStart };
      const ci = slots.findIndex((s) => s.toSuite === cur.toSuite && s.toPosition === cur.toPosition && s.anchorLineStart === cur.anchorLineStart);
      if (ci < 0) { return null; }
      return (direction === 'down' ? slots[ci + 1] : slots[ci - 1]) || null;
    }

    document.getElementById('test').addEventListener('click', () => vscode.postMessage({ command: 'test' }));
    document.getElementById('openText').addEventListener('click', () => vscode.postMessage({ command: 'openText' }));
    document.getElementById('pickSample').addEventListener('click', () => vscode.postMessage({ command: 'pickSample' }));
    for (const b of document.querySelectorAll('button.jump')) {
      b.addEventListener('click', () => vscode.postMessage({ command: 'openSource', line: Number(b.dataset.line) }));
    }
    // A recognized-row field posts its edit on change (blur/enter) — the provider shells lens rewrite
    // and applies the byte-stable result via a WorkspaceEdit (ADR 0076 §5).
    for (const inp of document.querySelectorAll('input.edit')) {
      inp.addEventListener('change', () => vscode.postMessage({
        command: 'edit',
        handler: inp.dataset.handler,
        lineStart: Number(inp.dataset.lineStart),
        lineEnd: Number(inp.dataset.lineEnd),
        name: inp.dataset.name,
        value: inp.value,
        // The row's projection-time source (data-expect-src) — carried to lens rewrite as expect_src so a
        // stale coordinate (a shift in a dirty split view) is REFUSED, not silently mis-edited (F7).
        expectSrc: inp.dataset.expectSrc,
      }));
    }
    // ADR 0104 §2.3: the HL7 field picker button beside a path/segment input. It posts pickPath; the
    // provider runs a native cascading quick-pick, then applies the chosen path through the SAME edit
    // splice (no new artifact). The input is untouched, so free-text stays available.
    for (const b of document.querySelectorAll('button.pickpath')) {
      // Don't let the button's mousedown blur+commit the focused path input — that would post a racing
      // `edit` that shifts the row and staleness-refuses the pick (F7). The picked value supersedes any
      // uncommitted partial text the user had typed.
      b.addEventListener('mousedown', (ev) => ev.preventDefault());
      b.addEventListener('click', (ev) => {
        ev.stopPropagation(); // a picker click must not also (re)select the row
        const inp = b.parentElement && b.parentElement.querySelector('input.edit');
        vscode.postMessage({
          command: 'pickPath',
          handler: b.dataset.handler,
          lineStart: Number(b.dataset.lineStart),
          lineEnd: Number(b.dataset.lineEnd),
          name: b.dataset.name,
          value: inp ? inp.value : '',
          expectSrc: b.dataset.expectSrc,
          mode: b.dataset.mode,
        });
      });
    }
    // Per-row structural affordances — each posts a delete/move command. The provider runs it as a lone op
    // (never batched) and forces a full re-projection afterwards (ADR 0076 §5 v2). data-op maps to the
    // command; each carries the row's coordinates + projection-time source (F7 stale guard). (The per-row
    // ＋ was replaced by the top-of-lens INSERT TOOLBAR below.)
    // Up/down now WALK the step through the visible order, crossing block boundaries: they compute the
    // adjacent insertion slot (walkMove) and post it as a drag-to-target moveTo — the SAME verified
    // cross-suite path drag-and-drop uses (an arrow move IS a one-step keyboard drag). Trash deletes in place.
    for (const b of document.querySelectorAll('button.rowop')) {
      b.addEventListener('click', (ev) => {
        ev.stopPropagation(); // a control click must not also (re)select the row
        const op = b.dataset.op;
        const lineStart = Number(b.dataset.lineStart);
        if (op === 'deleteRow') {
          vscode.postMessage({ command: 'deleteRow', handler: b.dataset.handler, lineStart,
            lineEnd: Number(b.dataset.lineEnd), expectSrc: b.dataset.expectSrc });
          return;
        }
        if (op === 'moveUp' || op === 'moveDown') {
          const res = walkMove(stepsCtxRows(), lineStart, op === 'moveUp' ? 'up' : 'down');
          if (!res) { return; } // at the top/bottom of the handler, or the sole statement of its block — a no-op
          vscode.postMessage({ command: 'moveTo', handler: b.dataset.handler, lineStart,
            lineEnd: Number(b.dataset.lineEnd), toLineStart: res.anchorLineStart, toLineEnd: res.anchorLineEnd,
            toPosition: res.toPosition, toSuite: res.toSuite, expectSrc: b.dataset.expectSrc });
        }
      });
    }

    // ---- ROW SELECTION + INSERT TOOLBAR (ADR 0076 §5 / BACKLOG #222) --------------------------------
    // A single row is "selected" (the toolbar Add's insert location). Clicking a row's BODY selects it;
    // clicking its ↑/↓/🗑 controls or an editable input does NOT (they stop-propagate / are excluded).
    const rows = Array.from(document.querySelectorAll('li.row'));

    // Grey the ↑ / ↓ ONLY where the walk has nowhere to go: the very top / bottom of the handler, or a step
    // that is the sole statement of its block (moving it would empty the block — the engine refuses that).
    // Arrows now cross block boundaries, so a suite edge is NO LONGER a dead end (that was the old model that
    // threw "already last among its siblings"). walkMove is authoritative — a button is greyed iff it returns null.
    // Wrapped so a throw in the arrow-greying (the walk logic) can NEVER abort the row-selection + toolbar
    // enablement wiring that follows — that silent-abort is the class of bug that leaves the whole toolbar dead.
    try {
      (function disableArrowsAtWalkEnds() {
        const ctxRows = stepsCtxRows();
        for (const el of rows) {
          if (el.getAttribute('draggable') !== 'true') { continue; } // only movable rows carry ↑/↓
          const ls = Number(el.dataset.lineStart);
          const up = el.querySelector('button.rowop[data-op="moveUp"]');
          const down = el.querySelector('button.rowop[data-op="moveDown"]');
          if (up && !walkMove(ctxRows, ls, 'up')) { up.disabled = true; up.title = 'Already at the top'; }
          if (down && !walkMove(ctxRows, ls, 'down')) { down.disabled = true; down.title = 'Already at the bottom'; }
        }
      })();
    } catch (e) {
      vscode.postMessage({ command: 'stepsDiag', level: 'error', text: 'arrow-greying failed: ' + e });
    }

    let selected = null; // { handler, lineStart, lineEnd, expectSrc, kind }
    let selectedEl = null;
    const addBtn = document.getElementById('addAction');
    const sel = document.getElementById('insertAction');

    function selectRow(el) {
      if (!el) { return; }
      if (selectedEl) { selectedEl.classList.remove('selected'); }
      selectedEl = el;
      el.classList.add('selected');
      selected = {
        handler: el.dataset.handler,
        lineStart: Number(el.dataset.lineStart),
        lineEnd: Number(el.dataset.lineEnd),
        expectSrc: el.dataset.expectSrc,
        kind: el.dataset.kind,
        control: el.dataset.control,
      };
      updateAddState();
    }

    // Enable the toolbar Add only for a valid (item, selected row) pair: a chosen item, AND — for an
    // if-chain-only item (Else / Else If, data-anchor="if_chain") — an if/elif anchor. Mirrors the
    // right-click menu's greying so the two Add surfaces agree on what is legal (avoids an F6 toast).
    function updateAddState() {
      if (sel.value === '' || !selected) { addBtn.disabled = true; return; }
      const opt = sel.selectedOptions && sel.selectedOptions[0];
      const needsIfChain = !!(opt && opt.dataset.anchor === 'if_chain');
      const isIfChain = selected.kind === 'control' && (selected.control === 'if' || selected.control === 'elif');
      addBtn.disabled = needsIfChain && !isIfChain;
    }

    // ---- Steps block clipboard (webview-owned via vscode.setState — survives re-projection) ------------
    function getClipboard() {
      const st = vscode.getState() || {};
      return st.stepsClipboard || null;
    }
    function setClipboard(clip) {
      vscode.setState(Object.assign({}, vscode.getState() || {}, { stepsClipboard: clip }));
    }
    // A row is COPY/CUT-eligible iff it is MOVABLE (draggable and not a read-only Code step).
    function selectedIsMovable() {
      return !!selectedEl && selectedEl.getAttribute('draggable') === 'true' && selectedEl.dataset.kind !== 'code';
    }
    // A short label for the copy/cut/paste toast (mirrors stepsModel.blockLabel).
    function clipLabel(cap) {
      if (cap.kind === 'control') { return cap.control === 'for' ? 'the loop' : 'the ' + (cap.control || 'if') + ' block'; }
      return cap.lineCount > 1 ? cap.lineCount + ' steps' : '1 step';
    }
    function copySelected() {
      if (!selectedIsMovable()) { return; } // friendly no-op — never an error
      const cap = captureBlock(stepsCtxRows(), Number(selectedEl.dataset.lineStart));
      if (!cap) { return; }
      const label = clipLabel(cap);
      setClipboard({ source: cap.source, nesting: cap.nesting, kind: cap.kind, lineCount: cap.lineCount, label: label });
      vscode.postMessage({ command: 'copyBlock', text: 'MessageFoundry: copied ' + label + ' to the Steps clipboard.' });
    }
    function cutSelected() {
      if (!selectedIsMovable()) { return; }
      const cap = captureBlock(stepsCtxRows(), Number(selectedEl.dataset.lineStart));
      if (!cap) { return; }
      const label = clipLabel(cap);
      // Capture FIRST (synchronous setState) so the source is never lost even if the delete is refused.
      setClipboard({ source: cap.source, nesting: cap.nesting, kind: cap.kind, lineCount: cap.lineCount, label: label });
      vscode.postMessage({ command: 'cutInfo', text: 'MessageFoundry: cut ' + label + ' (kept on the Steps clipboard).' });
      // Then delete the selected row's own span — the engine's broadened delete removes a whole if/for block.
      vscode.postMessage({
        command: 'deleteRow',
        handler: selectedEl.dataset.handler,
        lineStart: Number(selectedEl.dataset.lineStart),
        lineEnd: Number(selectedEl.dataset.lineEnd),
        expectSrc: selectedEl.dataset.expectSrc,
      });
    }
    function pasteSelected() {
      const clip = getClipboard();
      if (!clip || !selected) { return; } // empty clipboard / no selection → friendly no-op
      vscode.postMessage({
        command: 'paste',
        handler: selected.handler,
        lineStart: selected.lineStart,
        lineEnd: selected.lineEnd,
        kind: selected.kind,
        expectSrc: selected.expectSrc,
        block: clip.source,
        text: 'MessageFoundry: pasted ' + (clip.label || 'the steps') + '.',
      });
    }

    for (const el of rows) {
      el.addEventListener('click', (ev) => {
        // Clicks on a control or an input do their own thing — never (re)select from them.
        if (ev.target.closest('button, input, select, a')) { return; }
        selectRow(el);
      });
      el.addEventListener('focus', () => selectRow(el));
    }

    // ---- CROSS-SUITE DRAG-AND-DROP REORDER (ADR 0076 / move_row drag-to-target, #222 cross-suite) ----
    // A movable row/block (draggable="true") can be dropped at TOP LEVEL or INSIDE any control body — it
    // JOINS the landing suite at its indent (the engine re-indents + is authoritative, refusing an empty-
    // source / into-self / stale drop). The drop UX resolves the scope EXPLICITLY (this mirrors the pure
    // resolveDrop/scopeLabel in stepsModel.ts, the source of truth — the inline script can't import them):
    //  * a control HEADER gets a TRI-ZONE hit-test — top third → before the block (outer), middle → INTO the
    //    body as its first statement (one level deeper), bottom third → after the block (outer);
    //  * a leaf keeps the two-zone before/after (a send/return clamps to "before").
    // Three indicators show the landing scope BEFORE release: an insertion bar at the landing depth, a scope
    // pill naming the suite, and a left-border tint on every row of the landing suite.
    const INDENT_PX = 20;
    let dragSrc = null;
    let bar = null, pill = null;
    function ensureIndicators() {
      if (!bar) { bar = document.createElement('div'); bar.className = 'insertion-bar'; document.body.appendChild(bar); }
      if (!pill) { pill = document.createElement('div'); pill.className = 'scope-pill'; document.body.appendChild(pill); }
    }
    function clearIndicators() {
      if (bar) { bar.remove(); bar = null; }
      if (pill) { pill.remove(); pill = null; }
      for (const r of rows) { r.classList.remove('drop-scope'); }
    }
    function canDrop(target) {
      // Widened from same-suite to: same handler, not self, target draggable, and target NOT inside the
      // dragged block's own [start, end] span (so a block can't be dropped into itself). No suite check.
      if (!dragSrc || target === dragSrc || target.getAttribute('draggable') !== 'true') { return false; }
      if (target.dataset.kind === 'code') { return false; } // a Code step is read-only — never a drop target
      if (target.dataset.handler !== dragSrc.dataset.handler) { return false; }
      const ds = Number(dragSrc.dataset.lineStart), de = Number(dragSrc.dataset.lineEnd);
      const ts = Number(target.dataset.lineStart);
      return !(ds <= ts && ts <= de);
    }
    function rowByLineStart(lineStart) {
      return rows.find((r) => Number(r.dataset.lineStart) === lineStart) || null;
    }
    function scopeLabel(landingDepth, landingSuiteId) {
      if (landingDepth === 0) { return 'top level'; }
      const header = rowByLineStart(Number(landingSuiteId));
      const t = header && header.querySelector('.title');
      return 'inside ' + (t && t.textContent ? t.textContent : 'this block');
    }
    // Mirror of resolveDrop: returns { anchorEl, position, toSuite, landingDepth } or null.
    function resolveDrop(target, ev) {
      if (!canDrop(target)) { return null; }
      const box = target.getBoundingClientRect();
      const frac = box.height > 0 ? (ev.clientY - box.top) / box.height : 0.5;
      const nesting = Number(target.dataset.nesting);
      const isControlHeader = target.dataset.kind === 'control' && target.getAttribute('draggable') === 'true';
      if (isControlHeader) {
        if (frac < 1 / 3) {
          return { anchorEl: target, position: 'before', toSuite: target.dataset.suite, landingDepth: nesting };
        }
        if (frac > 2 / 3) {
          return { anchorEl: target, position: 'after', toSuite: target.dataset.suite, landingDepth: nesting };
        }
        const bodySuiteId = String(Number(target.dataset.lineStart));
        const first = rows.find((r) => r.dataset.suite === bodySuiteId);
        if (!first) { return null; }
        return { anchorEl: first, position: 'before', toSuite: bodySuiteId, landingDepth: nesting + 1 };
      }
      const position = target.dataset.kind === 'send' ? 'before' : (frac > 0.5 ? 'after' : 'before');
      return { anchorEl: target, position, toSuite: target.dataset.suite, landingDepth: nesting };
    }
    // Mirror of insertionBarAnchor (stepsModel.ts, the source of truth): which ROW + edge the bar sits on.
    // Normally the anchor row's top (before) / bottom (after). BUT for the control-header "after the whole
    // block" gesture (bottom third of a for/if header) the engine lands the block AFTER the ENTIRE block, so
    // the bar must sit at the block's VISUAL bottom — its last body row — not the header's bottom (which is
    // directly above the body, indistinguishable from the middle-third "into body" bar). Walk the rows list
    // forward from the header while each is DEEPER (a body row) or an elif/else CONTINUATION at its nesting.
    function barAnchor(res) {
      const a = res.anchorEl;
      if (a.dataset.kind === 'control' && res.position === 'after') {
        const headerNesting = Number(a.dataset.nesting);
        const start = rows.indexOf(a);
        let lastBody = a;
        for (let i = start + 1; i < rows.length; i++) {
          const r = rows[i];
          const n = Number(r.dataset.nesting);
          const cont = n === headerNesting && (r.dataset.control === 'elif' || r.dataset.control === 'else');
          if (n > headerNesting || cont) { lastBody = r; } else { break; }
        }
        return { el: lastBody, edge: 'bottom' };
      }
      return { el: a, edge: res.position === 'after' ? 'bottom' : 'top' };
    }
    function showIndicators(res, ev) {
      ensureIndicators();
      const ol = res.anchorEl.closest('ol.rows');
      const olRect = ol.getBoundingClientRect();
      const anchor = barAnchor(res);
      const aRect = anchor.el.getBoundingClientRect();
      const left = olRect.left + res.landingDepth * INDENT_PX;
      bar.style.left = left + 'px';
      bar.style.width = Math.max(0, olRect.right - left) + 'px';
      bar.style.top = (anchor.edge === 'bottom' ? aRect.bottom : aRect.top) + 'px';
      pill.textContent = scopeLabel(res.landingDepth, res.toSuite);
      pill.style.left = (ev.clientX + 14) + 'px';
      pill.style.top = (ev.clientY + 14) + 'px';
      for (const r of rows) {
        r.classList.toggle('drop-scope', r.dataset.suite === res.toSuite);
      }
    }
    for (const el of rows) {
      if (el.getAttribute('draggable') === 'true') {
        el.addEventListener('dragstart', (ev) => {
          if (el.dataset.kind === 'code') {
            // A Code step is read-only in the Steps view — cancel the drag and point at the code editor.
            ev.preventDefault();
            vscode.postMessage({ command: 'codeLocked' });
            return;
          }
          dragSrc = el;
          el.classList.add('dragging');
          if (ev.dataTransfer) {
            ev.dataTransfer.effectAllowed = 'move';
            // Firefox won't start a drag unless some data is set; the payload itself is unused.
            try { ev.dataTransfer.setData('text/plain', el.dataset.lineStart || ''); } catch (e) {}
          }
        });
        el.addEventListener('dragend', () => {
          if (dragSrc) { dragSrc.classList.remove('dragging'); }
          dragSrc = null;
          clearIndicators();
        });
      }
      el.addEventListener('dragover', (ev) => {
        const res = resolveDrop(el, ev);
        if (!res) { return; }
        ev.preventDefault(); // signals a valid drop target
        if (ev.dataTransfer) { ev.dataTransfer.dropEffect = 'move'; }
        showIndicators(res, ev);
      });
      el.addEventListener('dragleave', (ev) => {
        // Only clear when the pointer actually leaves this row (not on a child-boundary crossing); the next
        // dragover repaints anyway. Keeping it simple: clear the scope tint on this row, bar/pill repaint.
        el.classList.remove('drop-scope');
      });
      el.addEventListener('drop', (ev) => {
        const res = resolveDrop(el, ev);
        if (!res) { return; }
        ev.preventDefault();
        const src = dragSrc;
        clearIndicators();
        vscode.postMessage({
          command: 'moveTo',
          handler: src.dataset.handler,
          lineStart: Number(src.dataset.lineStart),
          lineEnd: Number(src.dataset.lineEnd),
          toLineStart: Number(res.anchorEl.dataset.lineStart),
          toLineEnd: Number(res.anchorEl.dataset.lineEnd),
          toPosition: res.position,
          // The landing suite id the client intended — the engine's destination stale-guard (to_suite).
          toSuite: res.toSuite,
          // The moved row's projection-time source — carried to lens rewrite as expect_src (F7 stale guard).
          expectSrc: src.dataset.expectSrc,
        });
      });
    }

    // Default/restore selection. After a toolbar insert re-projects, the whole webview reloads, so the prior
    // selection is remembered via webview state: find the anchor row again by (handler + projected source)
    // and select the NEWLY INSERTED neighbour (next sibling for an "after" insert, previous for "before").
    // Otherwise DEFAULT-SELECT the LAST row of the FIRST handler so a valid insert location always exists.
    (function initialSelection() {
      const state = vscode.getState() || {};
      const hint = state.selectAfterInsert;
      if (hint) {
        vscode.setState(Object.assign({}, state, { selectAfterInsert: undefined }));
        const anchor = rows.find(
          (r) => r.dataset.handler === hint.handler && r.dataset.expectSrc === hint.anchorExpectSrc,
        );
        if (anchor) {
          const sib = hint.position === 'before' ? anchor.previousElementSibling : anchor.nextElementSibling;
          selectRow(sib && sib.classList.contains('row') ? sib : anchor);
          return;
        }
      }
      const firstHandlerRows = document.querySelector('section.handler ol.rows');
      if (firstHandlerRows) {
        const last = firstHandlerRows.querySelector('li.row:last-child');
        if (last) { selectRow(last); }
      }
    })();

    // The dropdown: "[select item]" (value "") disables Add; a real action enables it (R3).
    sel.addEventListener('change', updateAddState);
    addBtn.addEventListener('click', () => {
      if (sel.value === '' || !selected) { return; }
      const position = selected.kind === 'send' ? 'before' : 'after';
      // Remember what to select after the insert re-projects (the new neighbour of the anchor row).
      vscode.setState(Object.assign({}, vscode.getState() || {}, {
        selectAfterInsert: { handler: selected.handler, anchorExpectSrc: selected.expectSrc, position },
      }));
      vscode.postMessage({
        command: 'insertItem',
        itemId: sel.value,
        handler: selected.handler,
        lineStart: selected.lineStart,
        lineEnd: selected.lineEnd,
        expectSrc: selected.expectSrc,
        kind: selected.kind,
      });
    });

    // Filter: hide rows that don't match the query (segment / field path / action / Send target). Pure client-
    // side navigation over the projected rows — no .py change. The keydown guard already defers Ctrl+C/X/V/Z/Y
    // to native text editing while this input is focused, so typing here never triggers a Steps clipboard op.
    const filterInput = document.getElementById('stepsFilter');
    if (filterInput) {
      filterInput.addEventListener('input', () => {
        const q = filterInput.value.trim().toLowerCase();
        for (const el of document.querySelectorAll('li.row')) {
          const hay = ((el.textContent || '') + ' ' + (el.dataset.expectSrc || '')).toLowerCase();
          el.style.display = (!q || hay.indexOf(q) !== -1) ? '' : 'none';
        }
      });
    }

    // ---- ROW CONTEXT MENU (right-click) — a new surface onto the EXISTING row ops (#222 follow-up) ------
    // A right-click on a row SELECTS it (reusing selectRow) and opens the server-rendered #stepsCtxMenu at
    // the pointer. Every item posts the SAME insertToolbar / deleteRow / moveTo(walkMove) messages the
    // toolbar Add and the per-row ↑/↓/🗑 buttons post — NO second execution path. Enablement mirrors the
    // pure stepsModel.contextMenuEnablement (unit-tested there). Copy/Cut/Paste stay keyboard-served (they
    // are deliberately NOT in this menu). Dispatch helpers use the currently `selected` row. These post to
    // the SAME provider handlers, so the byte-stable lens-rewrite path + F7 stale guard are unchanged.
    function menuInsert(itemId, position) {
      if (!selected || !itemId || (position !== 'before' && position !== 'after')) { return; }
      // Remember which row to re-select after the insert re-projects (the new neighbour of the anchor),
      // exactly as the toolbar Add does — the position drives before/after neighbour selection.
      vscode.setState(Object.assign({}, vscode.getState() || {}, {
        selectAfterInsert: { handler: selected.handler, anchorExpectSrc: selected.expectSrc, position: position },
      }));
      vscode.postMessage({
        command: 'insertItem', itemId: itemId, position: position,
        handler: selected.handler, lineStart: selected.lineStart, lineEnd: selected.lineEnd,
        expectSrc: selected.expectSrc, kind: selected.kind,
      });
    }
    function menuDelete() {
      if (!selected) { return; }
      vscode.postMessage({ command: 'deleteRow', handler: selected.handler,
        lineStart: selected.lineStart, lineEnd: selected.lineEnd, expectSrc: selected.expectSrc });
    }
    function menuMove(direction) {
      if (!selectedEl) { return; }
      const res = walkMove(stepsCtxRows(), Number(selectedEl.dataset.lineStart), direction);
      if (!res) { return; } // at the top/bottom of the handler or the sole statement of its block — a no-op
      vscode.postMessage({ command: 'moveTo', handler: selectedEl.dataset.handler,
        lineStart: Number(selectedEl.dataset.lineStart), lineEnd: Number(selectedEl.dataset.lineEnd),
        toLineStart: res.anchorLineStart, toLineEnd: res.anchorLineEnd,
        toPosition: res.toPosition, toSuite: res.toSuite, expectSrc: selectedEl.dataset.expectSrc });
    }

    // Wrapped in try/catch → stepsDiag so a throw in the menu wiring can NEVER silently kill the row
    // selection / toolbar wiring above it (the class of bug this whole file guards against).
    try {
      (function wireContextMenu() {
        const menu = document.getElementById('stepsCtxMenu');
        if (!menu) { return; }
        const insertParents = Array.from(menu.querySelectorAll('.ctx-parent'));
        const itemByCmd = (cmd) => menu.querySelector('.ctx-item[data-cmd="' + cmd + '"]');
        const delItem = itemByCmd('deleteRow');
        const upItem = itemByCmd('moveUp');
        const downItem = itemByCmd('moveDown');
        let open = false;

        function closeSubmenus() {
          for (const s of menu.querySelectorAll('.ctx-sub')) { s.classList.remove('ctx-open'); }
        }
        // Open EXACTLY ONE submenu (mouse or keyboard) — the mutual-exclusion the CSS can't guarantee (a
        // focused parent + a hovered sibling would both reveal, overlapping). A disabled parent opens none.
        function openSubmenu(sub) {
          const btn = sub && sub.querySelector('.ctx-parent');
          for (const s of menu.querySelectorAll('.ctx-sub')) {
            s.classList.toggle('ctx-open', s === sub && !(btn && btn.disabled));
          }
        }
        function closeMenu() {
          if (!open) { return; }
          open = false;
          menu.hidden = true;
          menu.classList.remove('ctx-flip-sub');
          closeSubmenus();
        }
        function setDisabled(el, disabled) {
          if (!el) { return; }
          el.disabled = !!disabled;
          // A disabled Insert parent must also suppress its submenu (belt-and-suspenders with openSubmenu).
          const sub = el.closest('.ctx-sub');
          if (sub) { sub.classList.toggle('ctx-disabled', !!disabled); }
        }
        // The visible, ENABLED items at a level (top-level, or within one submenu) — for arrow navigation.
        function enabledItemsIn(container, topLevel) {
          return Array.from(container.querySelectorAll('.ctx-item')).filter(
            (b) => !b.disabled && (topLevel ? !b.closest('.ctx-submenu') : true));
        }
        function openMenu(el, x, y) {
          const kind = el.dataset.kind;
          const ls = Number(el.dataset.lineStart);
          const ctxRows = stepsCtxRows();
          // Mirrors stepsModel.contextMenuEnablement: Insert before always; Insert after not on a send
          // (dead code after the return); Delete only on an editable action/lookup/send row; ↑/↓ per walk.
          for (const p of insertParents) {
            setDisabled(p, p.dataset.sub === 'after' && kind === 'send');
          }
          const control = el.dataset.control;
          setDisabled(delItem, !(kind === 'action' || kind === 'lookup' || kind === 'send' || kind === 'diagnostic'));
          // ADR 0106: Else / Else If (data-anchor="if_chain") only apply to an if-chain anchor (an if/elif row).
          const isIfChain = kind === 'control' && (control === 'if' || control === 'elif');
          for (const c of menu.querySelectorAll('.ctx-item[data-anchor="if_chain"]')) {
            setDisabled(c, !isIfChain);
          }
          // Mirror isRowMovable: a code row (and an elif/else header) is NOT movable, even though walkMove
          // finds an adjacent slot for it (it is draggable only as a drag-interception marker). Gate the
          // ↑/↓ on the row's own movability so the menu agrees with the per-row buttons + the read-only contract.
          const rowMovable =
            kind === 'action' || kind === 'lookup' || kind === 'send' || kind === 'diagnostic' ||
            (kind === 'control' && (control === 'if' || control === 'for' || control === 'raise'));
          setDisabled(upItem, !rowMovable || !walkMove(ctxRows, ls, 'up'));
          setDisabled(downItem, !rowMovable || !walkMove(ctxRows, ls, 'down'));
          // Reveal (hidden=false) so it can be measured, then clamp into the viewport (flip up/left at edges).
          menu.hidden = false;
          menu.classList.remove('ctx-flip-sub');
          menu.style.left = '0px'; menu.style.top = '0px';
          const rect = menu.getBoundingClientRect();
          const vw = window.innerWidth, vh = window.innerHeight;
          let left = x, top = y;
          if (left + rect.width > vw - 4) { left = Math.max(4, vw - rect.width - 4); }
          if (top + rect.height > vh - 4) { top = Math.max(4, vh - rect.height - 4); }
          menu.style.left = left + 'px';
          menu.style.top = top + 'px';
          // Open submenus on whichever side has more room (default right; flip LEFT only when the right
          // can't fit the submenu AND the left is roomier — so a near-left-edge narrow column doesn't flip
          // into an even smaller gap). In an extremely narrow column neither side fully fits; we still pick
          // the roomier side and keyboard nav (→ / ↑↓ / Enter) reaches every item regardless.
          const SUBMENU_W = 156;
          const spaceRight = vw - (left + rect.width);
          if (spaceRight < SUBMENU_W && left > spaceRight) { menu.classList.add('ctx-flip-sub'); }
          closeSubmenus(); // start with the top level only (focusing a parent no longer auto-reveals it)
          open = true;
          const firstEnabled = menu.querySelector('.ctx-item:not(:disabled)');
          if (firstEnabled) { firstEnabled.focus(); }
        }

        for (const el of rows) {
          el.addEventListener('contextmenu', (ev) => {
            // DEFER to the native text menu inside an EDITABLE param input — right-click-to-paste must keep
            // working in the very fields the [blank] hint invites you to fill (mirrors the click/keydown
            // bails on inputs above). A read-only/disabled input still gets the row menu (nothing to edit).
            const field = ev.target.closest('input, textarea, select');
            if (field && !field.disabled) { return; }
            ev.preventDefault();
            ev.stopPropagation();
            selectRow(el);
            openMenu(el, ev.clientX, ev.clientY);
          });
        }

        // Submenu reveal is JS-controlled (mutually exclusive): hovering an Insert parent opens ITS submenu
        // and closes the other; hovering a top-level leaf (Delete / Move up / Move down) closes any submenu.
        // Moving the pointer INTO an open submenu stays within its .ctx-sub, so it does not close.
        for (const sub of menu.querySelectorAll('.ctx-sub')) {
          sub.addEventListener('mouseenter', () => openSubmenu(sub));
        }
        for (const leaf of menu.querySelectorAll('.ctx-item[data-cmd]')) {
          if (leaf.closest('.ctx-submenu')) { continue; } // the insert items INSIDE a submenu are not leaves
          leaf.addEventListener('mouseenter', () => closeSubmenus());
        }

        menu.addEventListener('click', (ev) => {
          const item = ev.target.closest('.ctx-item');
          if (!item || item.disabled) { return; }
          const cmd = item.dataset.cmd;
          if (cmd === 'insert') { menuInsert(item.dataset.itemId, item.dataset.position); }
          else if (cmd === 'deleteRow') { menuDelete(); }
          else if (cmd === 'moveUp') { menuMove('up'); }
          else if (cmd === 'moveDown') { menuMove('down'); }
          else { return; } // an Insert PARENT — its submenu opens on hover/focus, a click is not an action
          closeMenu();
        });

        // Keyboard navigation while open: ↑/↓ move within the current level, → opens a submenu, ← returns.
        menu.addEventListener('keydown', (ev) => {
          if (!open) { return; }
          const focused = document.activeElement;
          const inSub = focused && focused.closest('.ctx-submenu');
          if (ev.key === 'ArrowDown' || ev.key === 'ArrowUp') {
            ev.preventDefault();
            const list = inSub ? enabledItemsIn(inSub, false) : enabledItemsIn(menu, true);
            if (!list.length) { return; }
            let i = list.indexOf(focused);
            i = ev.key === 'ArrowDown' ? (i + 1) % list.length : (i - 1 + list.length) % list.length;
            if (!inSub) { closeSubmenus(); } // moving among top-level items closes any open submenu
            list[i].focus();
          } else if (ev.key === 'ArrowRight' && focused && focused.classList.contains('ctx-parent') && !focused.disabled) {
            const wrap = focused.closest('.ctx-sub');
            openSubmenu(wrap); // reveal it (JS-controlled) before entering
            const items = enabledItemsIn(wrap.querySelector('.ctx-submenu'), false);
            if (items.length) { ev.preventDefault(); items[0].focus(); }
          } else if (ev.key === 'ArrowLeft' && inSub) {
            ev.preventDefault();
            const parent = inSub.closest('.ctx-sub').querySelector('.ctx-parent');
            closeSubmenus();
            if (parent) { parent.focus(); }
          }
        });

        // Dismiss: outside click (mousedown catches it before a row re-selects), Escape, scroll, resize, blur.
        document.addEventListener('mousedown', (ev) => {
          if (open && !menu.contains(ev.target)) { closeMenu(); }
        });
        document.addEventListener('keydown', (ev) => {
          if (open && ev.key === 'Escape') {
            ev.preventDefault();
            closeMenu();
            if (selectedEl) { selectedEl.focus(); } // return focus to the row for continuity
          }
        });
        window.addEventListener('scroll', () => closeMenu(), true);
        window.addEventListener('resize', () => closeMenu());
        window.addEventListener('blur', () => closeMenu());
      })();
    } catch (e) {
      vscode.postMessage({ command: 'stepsDiag', level: 'error', text: 'context-menu wiring failed: ' + e });
    }

