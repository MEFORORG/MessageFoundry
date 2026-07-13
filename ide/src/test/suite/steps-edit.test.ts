import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

import {
  ADD_MENU_CATALOG,
  EditLoopGuard,
  INSERTABLE_ACTIONS,
  INSERT_ACTION_LABELS,
  STRUCTURAL_OPS,
  TOOLBAR_INSERT_DEFAULTS,
  blockExtent,
  blockLabel,
  buildDeleteRequest,
  buildEditRequest,
  buildHandlerViewModels,
  buildInsertRequest,
  buildMoveRequest,
  buildMoveToRequest,
  buildPasteRequest,
  buildToolbarInsertRequest,
  canDropRow,
  captureBlock,
  contextMenuEnablement,
  drainEdits,
  editableParamNames,
  insertionBarAnchor,
  isRowEditable,
  isRowMovable,
  opForcesReprojection,
  parseRewriteResult,
  physicalLines,
  renderRowHtml,
  renderStepsContextMenuHtml,
  resolveDrop,
  scopeLabel,
  walkMove,
  type BlockCaptureRow,
  type ClipboardBlock,
  type EditMessage,
  type LensParseResult,
  type LensRow,
  type RowDropContext,
  type RowViewModel,
  type StructuralMessage,
} from "../../stepsModel";

// Phase-3 editing (ADR 0076 §5 / #222) — the pure, vscode-free half exercised node-side (the CI ide job
// has no Python, so the `lens rewrite` CLI boundary is a canned output). Covers: the edit → `lens rewrite`
// request mapping, which rows/params are editable (code/control offer NONE), the CLI-result parse
// (rewritten source vs refusal), the one-edit-at-a-time + update-loop guard, and that the rendered form
// emits an enabled input only for a recognized row's editable field.

const FIXTURE_DIR = path.join(__dirname, "..", "..", "..", "src", "test", "fixtures", "lens");

function loadFixture(name: string): LensParseResult {
  return JSON.parse(
    fs.readFileSync(path.join(FIXTURE_DIR, `${name}.json`), "utf8"),
  ) as LensParseResult;
}

function syntheticSource(parse: LensParseResult): string {
  let maxLine = 1;
  for (const h of parse.handlers) {
    for (const r of h.rows) {
      maxLine = Math.max(maxLine, r.line_end, h.def_line);
    }
  }
  return Array.from({ length: maxLine }, (_, i) => `line_${i + 1}`).join("\n");
}

suite("Steps edit — the webview edit → lens rewrite request mapping", () => {
  test("a field change maps to a single-param set_params edit spec", () => {
    const msg: EditMessage = {
      command: "edit",
      handler: "enrich",
      lineStart: 6,
      lineEnd: 6,
      name: "dst",
      value: "NK1-3.1",
    };
    assert.deepStrictEqual(buildEditRequest(msg), {
      handler: "enrich",
      line_start: 6,
      line_end: 6,
      op: "set_params",
      params: { dst: "NK1-3.1" },
    });
  });

  test("a send row's synthetic `to` field maps to a `to` param edit", () => {
    const msg: EditMessage = {
      command: "edit",
      handler: "acme_adt_handler",
      lineStart: 29,
      lineEnd: 29,
      name: "to",
      value: "OB_NEW",
    };
    assert.strictEqual(buildEditRequest(msg).params.to, "OB_NEW");
  });
});

suite("Steps edit — which rows/params are editable (code/control are read-only)", () => {
  test("isRowEditable: action/lookup/send yes; code/control no", () => {
    assert.strictEqual(isRowEditable("action"), true);
    assert.strictEqual(isRowEditable("lookup"), true);
    assert.strictEqual(isRowEditable("send"), true);
    assert.strictEqual(isRowEditable("code"), false);
    assert.strictEqual(isRowEditable("control"), false);
  });

  test("action/lookup rows expose every param; code/control expose none", () => {
    const action: LensRow = {
      kind: "action",
      action: "copy_field",
      params: { src: "PID-5.1", dst: "NK1-2.1" },
      line_start: 2,
      line_end: 2,
      nesting: 0,
    };
    assert.deepStrictEqual(editableParamNames(action), ["src", "dst"]);

    const lookup: LensRow = {
      kind: "lookup",
      call: "db_lookup",
      params: { connection: "MPI", statement: "select 1", params: "{}" },
      line_start: 3,
      line_end: 3,
      nesting: 0,
    };
    assert.deepStrictEqual(editableParamNames(lookup), ["connection", "statement", "params"]);

    const code: LensRow = { kind: "code", line_start: 4, line_end: 4, nesting: 0 };
    const control: LensRow = {
      kind: "control",
      control: "if",
      test_src: "msg['A']",
      recognized: true,
      line_start: 5,
      line_end: 5,
      nesting: 0,
    };
    assert.deepStrictEqual(editableParamNames(code), []);
    assert.deepStrictEqual(editableParamNames(control), []);
  });

  test("F6: only LITERAL params are offered as editable; expression/list slots are not", () => {
    // A db_lookup whose `params` arg is a `{...}` dict (an expression) — editing it as a scalar always
    // refuses on the engine side, so it must NOT render as an enabled input (the contract flags the two
    // literal params only).
    const lookup: LensRow = {
      kind: "lookup",
      call: "db_lookup",
      params: { connection: "MPI", statement: "select 1", params: '{"id": msg["PID-3.1"]}' },
      literal_params: ["connection", "statement"],
      line_start: 3,
      line_end: 3,
      nesting: 0,
    };
    assert.deepStrictEqual(editableParamNames(lookup), ["connection", "statement"]);

    // split_field's `dests` is a list literal (an `ast.List`, not a Constant) — also excluded.
    const split: LensRow = {
      kind: "action",
      action: "split_field",
      params: { src: "PID-5", sep: "^", dests: ["PID-5.1", "PID-5.2"] },
      literal_params: ["src", "sep"],
      line_start: 2,
      line_end: 2,
      nesting: 0,
    };
    assert.deepStrictEqual(editableParamNames(split), ["src", "sep"]);

    // The enabled input is emitted ONLY for the literal fields; the expression field stays disabled.
    const vm = buildHandlerViewModels(
      { module: "m", handlers: [{ handler: "h", module: "m", def_line: 1, rows: [lookup] }] },
      "line_1\nline_2\nline_3",
    )[0];
    const html = renderRowHtml(vm.rows[0], "h");
    assert.ok(html.includes('data-name="connection"'), "the literal `connection` field is editable");
    assert.ok(html.includes('data-name="statement"'), "the literal `statement` field is editable");
    assert.ok(
      !html.includes('data-name="params"'),
      "the expression `params` field must NOT be an enabled input (it would guarantee a refusal, F6)",
    );
  });

  test("ADR 0104 §2.3: the HL7 field picker button renders on a path slot, and ONLY there", () => {
    const render = (row: LensRow): string =>
      renderRowHtml(
        buildHandlerViewModels(
          { module: "m", handlers: [{ handler: "h", module: "m", def_line: 1, rows: [row] }] },
          "line_1\nline_2",
        )[0].rows[0],
        "h",
      );

    // set_field: the `path` literal slot gets a pick button; the `value` slot does not.
    const html = render({
      kind: "action",
      action: "set_field",
      params: { path: "PID-3.1", value: "X" },
      literal_params: ["path", "value"],
      line_start: 2,
      line_end: 2,
      nesting: 0,
    });
    assert.strictEqual(
      (html.match(/class="pickpath"/g) ?? []).length,
      1,
      "exactly one pick button — on `path`, never on `value`",
    );
    assert.ok(
      html.includes('data-name="path" data-mode="path"'),
      "the button targets the path slot in path mode",
    );
    assert.ok(html.includes('data-name="path" value="PID-3.1"'), "path stays a free-text input too");
    assert.ok(html.includes('data-name="value" value="X"'), "value stays a plain free-text input");

    // An expression-valued path (not in literal_params) is neither an editable input nor pickable (F6).
    const exprHtml = render({
      kind: "action",
      action: "set_field",
      params: { path: 'f"PID-{i}"', value: "X" },
      literal_params: ["value"],
      line_start: 2,
      line_end: 2,
      nesting: 0,
    });
    assert.ok(!exprHtml.includes('class="pickpath"'), "an expression-valued path gets no picker");

    // delete_segment: the segment_id slot gets a SEGMENT-only picker (no field/component).
    const delHtml = render({
      kind: "action",
      action: "delete_segment",
      params: { segment_id: "ZAL" },
      literal_params: ["segment_id"],
      line_start: 2,
      line_end: 2,
      nesting: 0,
    });
    assert.ok(delHtml.includes('data-mode="segment"'), "delete_segment offers a segment-only picker");

    // code_lookup is a LOOKUP row (its recognized name is in `call`, not `action`) — its path slot still
    // gets the picker (pickMode keys off the recognized name, action ?? call).
    const lookupHtml = render({
      kind: "lookup",
      call: "code_lookup",
      params: { path: "PID-8", table: "gender" },
      literal_params: ["path", "table"],
      line_start: 2,
      line_end: 2,
      nesting: 0,
    });
    assert.ok(lookupHtml.includes('class="pickpath"'), "code_lookup's path slot gets a picker");
    assert.ok(lookupHtml.includes('data-name="path" data-mode="path"'), "code_lookup path picker, path mode");

    // db_lookup (no HL7 path param) gets NO picker — a lookup row without a pickable slot is untouched.
    const dbHtml = render({
      kind: "lookup",
      call: "db_lookup",
      params: { connection: "C", statement: "select 1", params: "{}" },
      literal_params: ["connection", "statement"],
      line_start: 2,
      line_end: 2,
      nesting: 0,
    });
    assert.ok(!dbHtml.includes('class="pickpath"'), "db_lookup gets no picker (no HL7 path param)");

    // A code row never gets a picker (nothing editable at all).
    assert.ok(
      !render({ kind: "code", line_start: 2, line_end: 2, nesting: 0 }).includes('class="pickpath"'),
      "a code row never gets a picker button",
    );
  });

  test("a contract without literal_params (older engine / hand-built row) stays all-editable", () => {
    const action: LensRow = {
      kind: "action",
      action: "copy_field",
      params: { src: "PID-5.1", dst: "NK1-2.1" },
      line_start: 2,
      line_end: 2,
      nesting: 0,
    };
    assert.deepStrictEqual(editableParamNames(action), ["src", "dst"]);
  });

  test("a send row is editable only with exactly one static destination", () => {
    const single: LensRow = {
      kind: "send",
      outbounds: ["OB_A"],
      line_start: 2,
      line_end: 2,
      nesting: 0,
    };
    const many: LensRow = {
      kind: "send",
      outbounds: ["OB_A", "OB_B"],
      line_start: 3,
      line_end: 3,
      nesting: 0,
    };
    const dynamic: LensRow = { kind: "send", outbounds: [], line_start: 4, line_end: 4, nesting: 0 };
    assert.deepStrictEqual(editableParamNames(single), ["to"]);
    assert.deepStrictEqual(editableParamNames(many), []); // list-of-sends is out of v1 edit scope
    assert.deepStrictEqual(editableParamNames(dynamic), []); // dynamic destination not editable
  });

  test("the adt sample's code + control rows carry no editable params (read-only)", () => {
    const parse = loadFixture("adt");
    const vm = buildHandlerViewModels(parse, syntheticSource(parse))[0];
    for (const row of vm.rows) {
      if (row.kind === "code" || row.kind === "control") {
        assert.deepStrictEqual(row.editableParams ?? [], [], `${row.kind} row must be read-only`);
      }
    }
    // ...and its single send row IS editable.
    const send = vm.rows.find((r) => r.kind === "send");
    assert.ok(send);
    assert.deepStrictEqual(send!.editableParams, ["to"]);
  });
});

suite("Steps edit — rendered form emits an enabled input only for an editable field", () => {
  test("a recognized send row renders an enabled input carrying its edit coordinates", () => {
    const parse = loadFixture("IB_ACME_ADT");
    const vm = buildHandlerViewModels(parse, syntheticSource(parse))[0];
    const html = renderRowHtml(vm.rows[0], vm.handler);
    assert.ok(html.includes('class="edit"'), "the send `to` field is an enabled input");
    assert.ok(html.includes('data-name="to"'));
    assert.ok(html.includes('data-handler="acme_adt_handler"'));
    assert.ok(html.includes('data-line-start="29"') && html.includes('data-line-end="29"'));
  });

  test("a code row renders no editable input (stays read-only)", () => {
    const codeRow: RowViewModel = {
      index: 0,
      kind: "code",
      nesting: 0,
      lineStart: 2,
      lineEnd: 2,
      title: "Code",
      params: [],
      code: "x = weird(msg)",
    };
    const html = renderRowHtml(codeRow, "h");
    assert.ok(!html.includes('class="edit"'), "a code row never exposes an editable field");
  });

  test("a control row renders no editable input (stays read-only)", () => {
    const parse = loadFixture("adt");
    const vm = buildHandlerViewModels(parse, syntheticSource(parse))[0];
    const control = vm.rows.find((r) => r.kind === "control");
    assert.ok(control);
    const html = renderRowHtml(control!, vm.handler);
    assert.ok(!html.includes('class="edit"'), "a control row never exposes an editable field");
  });

  test("omitting the handler name (the read-only caller) disables every field", () => {
    const parse = loadFixture("IB_ACME_ADT");
    const vm = buildHandlerViewModels(parse, syntheticSource(parse))[0];
    const html = renderRowHtml(vm.rows[0]); // no handler name → read-only projection
    assert.ok(!html.includes('class="edit"'), "no handler scope means no writable field");
  });
});

suite("Steps edit — parse the lens rewrite CLI result", () => {
  const REWRITTEN = 'def h(msg):\n    return Send("OB_NEW", msg)\n';

  test("exit 0 → the rewritten module source", () => {
    const outcome = parseRewriteResult({ stdout: REWRITTEN, stderr: "", code: 0 });
    assert.strictEqual(outcome.source, REWRITTEN);
    assert.strictEqual(outcome.error, undefined);
  });

  test("exit 1 with a JSON {error} → the refusal message (no source)", () => {
    const outcome = parseRewriteResult({
      stdout: '{"error": "row at lines 47-47 is a \'control\' row"}',
      stderr: "",
      code: 1,
    });
    assert.strictEqual(outcome.source, undefined);
    assert.ok(outcome.error && outcome.error.includes("control"));
  });

  test("a non-zero exit with no JSON body falls back to stderr", () => {
    const outcome = parseRewriteResult({
      stdout: "",
      stderr: "workspace not trusted — MessageFoundry CLI disabled",
      code: 1,
    });
    assert.strictEqual(outcome.source, undefined);
    assert.ok(outcome.error && outcome.error.includes("not trusted"));
  });
});

suite("Steps edit — one-edit-at-a-time + update-loop guard", () => {
  test("beginEdit claims a single slot; a second concurrent edit is refused", () => {
    const guard = new EditLoopGuard();
    assert.strictEqual(guard.beginEdit(), true, "first edit claims the slot");
    assert.strictEqual(guard.isEditing, true);
    assert.strictEqual(guard.beginEdit(), false, "a second edit is dropped while one is in flight");
  });

  test("a document change during our own edit does NOT trigger a re-render (the loop is broken)", () => {
    const guard = new EditLoopGuard();
    assert.strictEqual(guard.shouldReactToDocumentChange(), true, "idle: react normally");
    guard.beginEdit();
    assert.strictEqual(
      guard.shouldReactToDocumentChange(),
      false,
      "our own in-flight WorkspaceEdit must not feed back into a re-render",
    );
    guard.endEdit();
    assert.strictEqual(guard.shouldReactToDocumentChange(), true, "after the edit settles, react again");
    assert.strictEqual(guard.beginEdit(), true, "the slot is free again");
  });

  test("F5: a second edit racing an in-flight rewrite is QUEUED (not dropped) and drained after", () => {
    const guard = new EditLoopGuard();
    const first: EditMessage = {
      command: "edit",
      handler: "h",
      lineStart: 6,
      lineEnd: 6,
      name: "dst",
      value: "A",
    };
    const second: EditMessage = { ...first, name: "src", value: "B" };
    // The provider's flow: begin the first, a second arrives while in flight → queue it.
    assert.strictEqual(guard.beginEdit(), true);
    assert.strictEqual(guard.beginEdit(), false, "one edit at a time");
    guard.queue(second);
    assert.strictEqual(guard.pendingCount, 1, "the racing edit is remembered, not silently lost");
    // Drain loop: after the first applies, takePending yields the queued edit, then empties.
    const drained = guard.takePending();
    assert.deepStrictEqual(drained, second, "the queued edit is applied after the in-flight one");
    assert.strictEqual(guard.takePending(), undefined, "nothing left to drain");
    guard.endEdit();
    assert.strictEqual(guard.beginEdit(), true, "slot free again once the queue is empty");
  });

  test("F5: re-typing the SAME field while in flight coalesces to the latest value", () => {
    const guard = new EditLoopGuard();
    const base: EditMessage = {
      command: "edit",
      handler: "h",
      lineStart: 6,
      lineEnd: 6,
      name: "dst",
      value: "v1",
    };
    guard.beginEdit();
    guard.queue({ ...base, value: "v1" });
    guard.queue({ ...base, value: "v2" }); // same field re-typed
    assert.strictEqual(guard.pendingCount, 1, "same field coalesces to one pending edit");
    assert.strictEqual(guard.takePending()?.value, "v2", "the latest typed value wins");
    // A DIFFERENT field, however, keeps its own pending slot.
    guard.queue({ ...base, name: "src", value: "x" });
    guard.queue({ ...base, name: "dst", value: "y" });
    assert.strictEqual(guard.pendingCount, 2, "distinct fields each retain a pending edit");
  });
});

suite("Steps edit — the stale-coordinate guard (F7)", () => {
  test("buildEditRequest carries the row's live-buffer source as expect_src when supplied", () => {
    const msg: EditMessage = {
      command: "edit",
      handler: "h",
      lineStart: 6,
      lineEnd: 6,
      name: "dst",
      value: "C",
    };
    const withSrc = buildEditRequest(msg, '    copy_field(msg, "A", "B")');
    assert.strictEqual(withSrc.expect_src, '    copy_field(msg, "A", "B")');
    // Omitting it (older/no-buffer caller) leaves expect_src absent — the engine skips the stale check.
    assert.strictEqual(buildEditRequest(msg).expect_src, undefined);
  });
});

// The F7 fix: expect_src must be the PROJECTION-TIME row source (what the user saw), threaded render →
// message → payload — NOT recomputed from the same live buffer sent as stdin (which made the engine
// compare the buffer against itself, a tautology that let a shifted same-shape row be silently edited).
// The `lens rewrite` CLI boundary has no Python here, so these exercise the pure decision/payload and
// model the engine's F7 comparison (physicalLines, mirroring messagefoundry/lens._physical_lines).

// Two identical-shape `copy_field` rows — the exact same-shape hazard the F7 guard protects against.
const F7_SOURCE = [
  "def enrich(msg):", //                          line 1
  '    copy_field(msg, "PID-5", "PID-6")', //     line 2  (row A — the one the input targets)
  '    copy_field(msg, "PID-5", "PID-7")', //     line 3  (row B — same shape, one line down)
].join("\n");

function f7Parse(): LensParseResult {
  const mk = (dst: string, line: number): LensRow => ({
    kind: "action",
    action: "copy_field",
    params: { src: "PID-5", dst },
    literal_params: ["src", "dst"],
    line_start: line,
    line_end: line,
    nesting: 1,
  });
  return {
    module: "m",
    handlers: [
      { handler: "enrich", module: "m", def_line: 1, rows: [mk("PID-6", 2), mk("PID-7", 3)] },
    ],
  };
}

suite("Steps edit — F7 wiring: the edit carries the projection-time row source", () => {
  test("the view-model attaches each row's projected source (engine newline model)", () => {
    const vm = buildHandlerViewModels(f7Parse(), F7_SOURCE)[0];
    assert.strictEqual(vm.rows[0].expectSrc, '    copy_field(msg, "PID-5", "PID-6")');
    assert.strictEqual(vm.rows[1].expectSrc, '    copy_field(msg, "PID-5", "PID-7")');
  });

  test("render → message → payload: buildEditRequest uses the PROJECTED source, not a buffer recompute", () => {
    const vm = buildHandlerViewModels(f7Parse(), F7_SOURCE)[0];
    // The webview echoes the projected source back on the edit message (from data-expect-src).
    const msg: EditMessage = {
      command: "edit",
      handler: "enrich",
      lineStart: 2,
      lineEnd: 2,
      name: "dst",
      value: "HACKED",
      expectSrc: vm.rows[0].expectSrc,
    };
    const req = buildEditRequest(msg);
    assert.strictEqual(
      req.expect_src,
      '    copy_field(msg, "PID-5", "PID-6")',
      "the payload carries the row as PROJECTED — the F7 guard's whole point",
    );
  });

  test("a stale (shifted) buffer → projected != buffer row → the engine refuses (pre-fix it was a tautology)", () => {
    const vm = buildHandlerViewModels(f7Parse(), F7_SOURCE)[0];
    const msg: EditMessage = {
      command: "edit",
      handler: "enrich",
      lineStart: 2,
      lineEnd: 2,
      name: "dst",
      value: "HACKED",
      expectSrc: vm.rows[0].expectSrc,
    };
    const req = buildEditRequest(msg);

    // The user deletes line 1 in a split view WITHOUT saving: the lens still shows the disk projection, so
    // the input for row A still carries line_start/end = 2, but row B has shifted UP into physical line 2.
    const liveBuffer = [
      '    copy_field(msg, "PID-5", "PID-6")', // was line 2 → now line 1
      '    copy_field(msg, "PID-5", "PID-7")', // was line 3 → now line 2  ← the shifted "wrong row"
    ].join("\n");
    // The engine's F7 check: the live buffer's row at [line_start, line_end], joined the same way.
    const engineActual = physicalLines(liveBuffer)
      .slice(req.line_start - 1, req.line_end)
      .join("\n");

    // FIX: the payload carries the PROJECTED source → differs from the shifted buffer row → engine REFUSES.
    assert.notStrictEqual(
      req.expect_src,
      engineActual,
      "projected row source must differ from the shifted buffer row so the guard fires",
    );
    // PRE-FIX contrast: applyOne recomputed expect_src from the SAME live buffer it sent as stdin, so
    // expect_src == the buffer's row == engineActual → the guard was tautological and always PASSED,
    // silently editing the wrong (shifted) row. That is exactly what this test would assert-fail on before
    // the fix (the fixed payload's expect_src no longer equals engineActual).
    const preFixReq = buildEditRequest({ ...msg, expectSrc: undefined }, engineActual);
    assert.strictEqual(
      preFixReq.expect_src,
      engineActual,
      "the old live-buffer recompute made expect_src == the buffer row (the tautology)",
    );

    // On the refusal the CLI returns {error} + exit 1: no source → applyOne writes nothing (document
    // unchanged) and re-projects; only the error toast is shown.
    const outcome = parseRewriteResult({
      stdout:
        '{"error": "the row\'s source no longer matches the editor buffer (stale coordinates) — re-project the Steps view and retry"}',
      stderr: "",
      code: 1,
    });
    assert.strictEqual(outcome.source, undefined, "a stale-coordinate refusal carries no source to write");
    assert.ok(outcome.error && outcome.error.includes("stale coordinates"));
  });
});

suite("Steps edit — drainEdits survives an unexpected applyEdit rejection (does not strand a queued edit)", () => {
  test("a rejected apply releases the slot AND keeps draining the pending queue", async () => {
    const guard = new EditLoopGuard();
    const applied: string[] = [];
    const errors: unknown[] = [];
    const first: EditMessage = {
      command: "edit",
      handler: "h",
      lineStart: 6,
      lineEnd: 6,
      name: "dst",
      value: "A",
    };
    const second: EditMessage = { ...first, name: "src", value: "B" };

    const apply = async (msg: EditMessage): Promise<void> => {
      applied.push(msg.name);
      if (msg.name === "dst") {
        // A second field-edit lands while the first is in flight (queued), then the first's WorkspaceEdit
        // REJECTS — the pre-fix inline loop let that propagate into finally{endEdit()}, leaving `second`
        // un-drained until the user typed again. drainEdits must swallow it and keep going.
        guard.queue(second);
        throw new Error("applyEdit rejected");
      }
    };

    await drainEdits(guard, first, apply, (e) => errors.push(e));

    assert.deepStrictEqual(
      applied,
      ["dst", "src"],
      "the queued edit is still applied after the first apply rejected",
    );
    assert.strictEqual(errors.length, 1, "the unexpected rejection is surfaced via onError, not swallowed silently");
    assert.strictEqual(guard.isEditing, false, "the single-edit slot is released even though apply threw");
    assert.strictEqual(guard.beginEdit(), true, "a later edit can claim the slot (no permanent wedge)");
  });

  test("while an edit is in flight, a fresh drainEdits call queues (does not race) and is drained by the running loop", async () => {
    const guard = new EditLoopGuard();
    const applied: string[] = [];
    const a: EditMessage = { command: "edit", handler: "h", lineStart: 1, lineEnd: 1, name: "dst", value: "1" };
    const b: EditMessage = { ...a, name: "src", value: "2" };

    let releaseFirst: (() => void) | undefined;
    const apply = async (msg: EditMessage): Promise<void> => {
      applied.push(msg.name);
      if (msg.name === "dst") {
        // Hold the first apply open so the second drainEdits call arrives mid-flight.
        await new Promise<void>((resolve) => {
          releaseFirst = resolve;
        });
      }
    };

    const run1 = drainEdits(guard, a, apply);
    // Second edit arrives while the first is still applying → its own drainEdits call must queue, not race.
    const run2 = drainEdits(guard, b, apply);
    releaseFirst?.();
    await Promise.all([run1, run2]);

    assert.deepStrictEqual(applied, ["dst", "src"], "the second edit is drained by the first loop, exactly once");
    assert.strictEqual(guard.isEditing, false, "the slot is released after the queue empties");
  });
});

suite("Steps v2 — a structural op discards param edits queued mid-op (orphaned-queue hazard)", () => {
  test("clearPending drops the queue without applying it", () => {
    const guard = new EditLoopGuard();
    guard.beginEdit();
    guard.queue({ command: "edit", handler: "h", lineStart: 7, lineEnd: 7, name: "value", value: "X" });
    assert.strictEqual(guard.pendingCount, 1);
    guard.clearPending();
    assert.strictEqual(guard.pendingCount, 0, "the queued edit is dropped, not retained");
    assert.strictEqual(guard.takePending(), undefined, "nothing to drain after a clear");
  });

  test("a param edit queued DURING a structural op is discarded on re-projection, not applied on stale coords", async () => {
    // Mirror the provider's applyStructural sequence with the pure guard (which imports vscode and is
    // not unit-testable directly): the structural op claims the single slot; a param edit arrives
    // mid-flight (drainEdits queues it, since beginEdit is refused while the op holds the slot); the op
    // completes → clearPending() + endEdit() (then a forced re-projection rebuilds the webview). The
    // stale PRE-op edit must NOT survive to be applied against shifted coordinates by a later, unrelated
    // param edit. This is the exact orphaned-queue defect the fix closes (ADR 0076 §5 v2).
    const guard = new EditLoopGuard();
    const applied: string[] = [];
    const apply = async (m: EditMessage): Promise<void> => {
      applied.push(`${m.name}@${m.lineStart}`);
    };

    // applyStructural claims the slot.
    assert.strictEqual(guard.beginEdit(), true);
    // A param edit on the PRE-op line 7 arrives mid-flight → drainEdits sees the slot held → queues it.
    const staleEdit: EditMessage = {
      command: "edit",
      handler: "h",
      lineStart: 7,
      lineEnd: 7,
      name: "value",
      value: "STALE",
    };
    await drainEdits(guard, staleEdit, apply);
    assert.strictEqual(guard.pendingCount, 1, "the mid-op param edit was queued, not applied");
    assert.strictEqual(applied.length, 0, "nothing applied while the structural op holds the slot");

    // applyStructural completes: the FIX drops the orphaned queue BEFORE releasing the slot.
    guard.clearPending();
    guard.endEdit();

    // A later, unrelated fresh param edit (against the RE-PROJECTED line 6) drains.
    const freshEdit: EditMessage = {
      command: "edit",
      handler: "h",
      lineStart: 6,
      lineEnd: 6,
      name: "dst",
      value: "FRESH",
    };
    await drainEdits(guard, freshEdit, apply);

    // Only the fresh edit ran; the stale pre-op edit (value@7) was discarded — never applied on stale
    // coords. Pre-fix (no clearPending) the drain would also apply "value@7" against shifted rows.
    assert.deepStrictEqual(
      applied,
      ["dst@6"],
      "the orphaned pre-op edit must NOT be applied after re-projection",
    );
  });
});

// ---- phase 3 v2: STRUCTURAL ops (insert/delete/move) — request mapping + re-projection + affordances

suite("Steps v2 — structural op → lens rewrite request mapping", () => {
  const base = { handler: "enrich", lineStart: 7, lineEnd: 7, expectSrc: '    set_field(msg, "A", "B")' };

  test("delete maps to a delete_row spec carrying expect_src (F7)", () => {
    const msg: StructuralMessage = { command: "deleteRow", ...base };
    assert.deepStrictEqual(buildDeleteRequest(msg), {
      handler: "enrich",
      line_start: 7,
      line_end: 7,
      op: "delete_row",
      expect_src: '    set_field(msg, "A", "B")',
    });
  });

  test("delete omits expect_src when the message has none", () => {
    const msg: StructuralMessage = { command: "deleteRow", handler: "h", lineStart: 3, lineEnd: 3 };
    assert.strictEqual(buildDeleteRequest(msg).expect_src, undefined);
  });

  test("move up/down maps to a move_row spec with the direction", () => {
    const up = buildMoveRequest({ command: "moveRow", direction: "up", ...base });
    assert.strictEqual(up.op, "move_row");
    assert.strictEqual(up.direction, "up");
    assert.strictEqual(up.expect_src, '    set_field(msg, "A", "B")');
    const down = buildMoveRequest({ command: "moveRow", direction: "down", ...base });
    assert.strictEqual(down.direction, "down");
  });

  test("move without a direction throws (a guard against a malformed message)", () => {
    assert.throws(() => buildMoveRequest({ command: "moveRow", ...base }));
  });

  test("drag-and-drop maps to a move_row spec with the drop target + position (no direction)", () => {
    const req = buildMoveToRequest({
      command: "moveTo",
      handler: "enrich",
      lineStart: 7,
      lineEnd: 7,
      toLineStart: 9,
      toLineEnd: 9,
      toPosition: "after",
      expectSrc: '    set_field(msg, "A", "B")',
    });
    assert.deepStrictEqual(req, {
      handler: "enrich",
      line_start: 7,
      line_end: 7,
      op: "move_row",
      to_line_start: 9,
      to_line_end: 9,
      to_position: "after",
      expect_src: '    set_field(msg, "A", "B")',
    });
    assert.strictEqual(req.direction, undefined); // the DnD form never carries a direction
  });

  test("drag-and-drop defaults to_line_end to to_line_start when the target is a single line", () => {
    const req = buildMoveToRequest({
      command: "moveTo",
      handler: "h",
      lineStart: 5,
      lineEnd: 5,
      toLineStart: 8,
      toPosition: "before",
    });
    assert.strictEqual(req.to_line_end, 8);
    assert.strictEqual(req.expect_src, undefined); // omitted when the message has none
    assert.strictEqual(req.to_suite, undefined); // omitted when the message has none
  });

  test("cross-suite drag carries to_suite (the destination stale-guard) when supplied", () => {
    const req = buildMoveToRequest({
      command: "moveTo",
      handler: "enrich",
      lineStart: 8,
      lineEnd: 8,
      toLineStart: 7,
      toLineEnd: 7,
      toPosition: "after",
      toSuite: "6",
      expectSrc: '    set_field(msg, "B", "2")',
    });
    assert.strictEqual(req.to_suite, "6", "the intended landing suite id rides as to_suite");
    // ...and is OMITTED when the message has none, so the no-toSuite mapping test stays byte-identical.
    const bare = buildMoveToRequest({
      command: "moveTo",
      handler: "enrich",
      lineStart: 8,
      lineEnd: 8,
      toLineStart: 7,
      toPosition: "after",
    });
    assert.ok(!("to_suite" in bare), "no toSuite → no to_suite key (backward-compatible payload)");
  });

  test("drag-and-drop without a valid target/position throws (guard against a malformed message)", () => {
    assert.throws(() =>
      buildMoveToRequest({ command: "moveTo", handler: "h", lineStart: 5, lineEnd: 5 }),
    );
    assert.throws(() =>
      buildMoveToRequest({
        command: "moveTo",
        handler: "h",
        lineStart: 5,
        lineEnd: 5,
        toLineStart: 8,
        toPosition: "sideways" as "before",
      }),
    );
  });

  test("insert maps an anchor + action + params to an insert_row spec (position after)", () => {
    const req = buildInsertRequest(
      { handler: "enrich", lineStart: 6, lineEnd: 6, expectSrc: '    copy_field(msg, "A", "B")' },
      "set_field",
      { path: "MSH-3", value: "MEFOR" },
    );
    assert.deepStrictEqual(req, {
      handler: "enrich",
      line_start: 6,
      line_end: 6,
      op: "insert_row",
      position: "after",
      action: "set_field",
      params: { path: "MSH-3", value: "MEFOR" },
      expect_src: '    copy_field(msg, "A", "B")',
    });
  });

  test("the add-row form offers only scalar-param vocabulary actions", () => {
    assert.deepStrictEqual(INSERTABLE_ACTIONS.copy_field, ["src", "dst"]);
    assert.deepStrictEqual(INSERTABLE_ACTIONS.set_field, ["path", "value"]);
    // list-valued / expression-arg actions are NOT in the quick form (they need text editing).
    assert.ok(!("split_field" in INSERTABLE_ACTIONS));
    assert.ok(!("db_lookup" in INSERTABLE_ACTIONS));
  });
});

suite("Steps toolbar — the top-of-lens INSERT toolbar (Corepoint-style Add)", () => {
  test("INSERT_ACTION_LABELS is the ordered dropdown catalog (value + friendly label)", () => {
    // Trimmed to the actions the engine inserts in their NATIVE, import-free form (ADR 0089 Phase A) — the
    // wrapper-only verbs (append_to_field / convert_case / format_date / copy_segment) return with Phase B.
    assert.deepStrictEqual(INSERT_ACTION_LABELS, [
      { value: "set_field", label: "Set Field" },
      { value: "copy_field", label: "Copy Field" },
      { value: "delete_segment", label: "Delete Segment" },
    ]);
  });

  test("the catalog is the native-insertable SUBSET of INSERTABLE_ACTIONS (no split_field / code_lookup)", () => {
    const catalog = INSERT_ACTION_LABELS.map((o) => o.value);
    // The dropdown offers only the Phase-A native-insertable actions — a SUBSET of INSERTABLE_ACTIONS (the
    // wrapper-only verbs stay defined for their param templates but are not offered until Phase B).
    assert.deepStrictEqual([...catalog].sort(), ["copy_field", "delete_segment", "set_field"]);
    const keys = new Set(Object.keys(INSERTABLE_ACTIONS));
    assert.ok(
      catalog.every((v) => keys.has(v)),
      "every offered action is a known INSERTABLE_ACTIONS entry",
    );
    assert.ok(!catalog.includes("split_field"), "split_field is text-editor-only (list dests)");
    assert.ok(!catalog.includes("code_lookup"), "code_lookup is text-editor-only (dict table)");
  });

  test("TOOLBAR_INSERT_DEFAULTS carries a default template per action (matching its param names)", () => {
    assert.deepStrictEqual(TOOLBAR_INSERT_DEFAULTS.set_field, { path: "", value: "" });
    assert.deepStrictEqual(TOOLBAR_INSERT_DEFAULTS.copy_field, { src: "", dst: "" });
    assert.deepStrictEqual(TOOLBAR_INSERT_DEFAULTS.append_to_field, { path: "", suffix: "" });
    assert.deepStrictEqual(TOOLBAR_INSERT_DEFAULTS.convert_case, { path: "", mode: "upper" });
    assert.deepStrictEqual(TOOLBAR_INSERT_DEFAULTS.format_date, { path: "", out_fmt: "" });
    assert.deepStrictEqual(TOOLBAR_INSERT_DEFAULTS.copy_segment, { segment_id: "" });
    assert.deepStrictEqual(TOOLBAR_INSERT_DEFAULTS.delete_segment, { segment_id: "" });
    // Each template's keys equal that action's INSERTABLE_ACTIONS param names (in order).
    for (const [action, params] of Object.entries(INSERTABLE_ACTIONS)) {
      assert.deepStrictEqual(Object.keys(TOOLBAR_INSERT_DEFAULTS[action]), params, action);
    }
  });

  test("buildToolbarInsertRequest inserts AFTER a non-send anchor, with defaults + expect_src (F7)", () => {
    const req = buildToolbarInsertRequest(
      { handler: "enrich", lineStart: 6, lineEnd: 6, expectSrc: '    copy_field(msg, "A", "B")', kind: "action" },
      "set_field",
    );
    assert.deepStrictEqual(req, {
      handler: "enrich",
      line_start: 6,
      line_end: 6,
      op: "insert_row",
      position: "after",
      action: "set_field",
      params: { path: "", value: "" },
      expect_src: '    copy_field(msg, "A", "B")',
    });
  });

  test("buildToolbarInsertRequest inserts BEFORE a send anchor (the new action must precede the return)", () => {
    const req = buildToolbarInsertRequest(
      { handler: "enrich", lineStart: 9, lineEnd: 9, expectSrc: "    return Send(...)", kind: "send" },
      "convert_case",
    );
    assert.strictEqual(req.position, "before");
    assert.deepStrictEqual(req.params, { path: "", mode: "upper" });
    assert.strictEqual(req.expect_src, "    return Send(...)");
  });

  test("lookup/control/code anchors insert AFTER (only send is special)", () => {
    for (const kind of ["lookup", "control", "code"] as const) {
      const req = buildToolbarInsertRequest(
        { handler: "h", lineStart: 3, lineEnd: 3, kind },
        "copy_segment",
      );
      assert.strictEqual(req.position, "after", `${kind} anchor → after`);
    }
  });

  test("an anchor without expect_src omits it (no stale check)", () => {
    const req = buildToolbarInsertRequest(
      { handler: "h", lineStart: 2, lineEnd: 2, kind: "action" },
      "delete_segment",
    );
    assert.strictEqual(req.expect_src, undefined);
    assert.deepStrictEqual(req.params, { segment_id: "" });
  });
});

// The right-click ROW CONTEXT MENU (ADR 0103) — the pure half: the explicit before/after insert mapping,
// the item-enablement matrix, the server-rendered menu template, and the [blank] placeholder. The webview
// WIRING (positioning, dismissal, keyboard) lives in media/stepsWebview.js and is NOT unit-tested here —
// like the file's other webview mirrors (walkMove/captureBlock DnD), it is verified manually; these
// node-side tests cover the pure model + the rendered markup it consumes.
suite("Steps context menu — explicit before/after insert (right-click, ADR 0103)", () => {
  const anchor = {
    handler: "enrich",
    lineStart: 6,
    lineEnd: 6,
    expectSrc: '    copy_field(msg, "A", "B")',
    kind: "action" as const,
  };

  test("an explicit 'before' position overrides the kind-derived default", () => {
    const req = buildToolbarInsertRequest(anchor, "set_field", "before");
    assert.strictEqual(req.position, "before");
    assert.deepStrictEqual(req.params, { path: "", value: "" });
    assert.strictEqual(req.expect_src, '    copy_field(msg, "A", "B")');
  });

  test("an explicit 'after' position is honored on a non-send anchor", () => {
    assert.strictEqual(buildToolbarInsertRequest(anchor, "set_field", "after").position, "after");
  });

  test("an explicit position is honored on a send anchor too (the pure fn stays literal)", () => {
    const send = { handler: "h", lineStart: 9, lineEnd: 9, kind: "send" as const };
    assert.strictEqual(buildToolbarInsertRequest(send, "set_field", "before").position, "before");
    assert.strictEqual(buildToolbarInsertRequest(send, "set_field", "after").position, "after");
  });

  test("omitting position keeps the toolbar Add's derived behavior byte-identical (backward compatible)", () => {
    assert.strictEqual(buildToolbarInsertRequest(anchor, "set_field").position, "after");
    const send = { handler: "h", lineStart: 9, lineEnd: 9, kind: "send" as const };
    assert.strictEqual(buildToolbarInsertRequest(send, "set_field").position, "before");
  });
});

suite("Steps context menu — item enablement matrix (ADR 0103)", () => {
  test("an editable action row that can walk both ways enables every item", () => {
    assert.deepStrictEqual(contextMenuEnablement("action", { canMoveUp: true, canMoveDown: true }), {
      insertBefore: true,
      insertAfter: true,
      deleteRow: true,
      moveUp: true,
      moveDown: true,
    });
  });

  test("a send row suppresses Insert after (dead code after the return) but stays deletable", () => {
    const e = contextMenuEnablement("send", { canMoveUp: true, canMoveDown: false });
    assert.strictEqual(e.insertBefore, true);
    assert.strictEqual(e.insertAfter, false);
    assert.strictEqual(e.deleteRow, true);
    assert.strictEqual(e.moveDown, false);
  });

  test("code/control rows are read-only: Insert both ways, but never Delete", () => {
    for (const kind of ["code", "control"] as const) {
      const e = contextMenuEnablement(kind, { canMoveUp: false, canMoveDown: false });
      assert.strictEqual(e.insertBefore, true, kind);
      assert.strictEqual(e.insertAfter, true, kind);
      assert.strictEqual(e.deleteRow, false, kind);
      assert.strictEqual(e.moveUp, false, kind);
      assert.strictEqual(e.moveDown, false, kind);
    }
  });

  test("move up/down follow the walk booleans verbatim", () => {
    const e = contextMenuEnablement("lookup", { canMoveUp: false, canMoveDown: true });
    assert.strictEqual(e.moveUp, false);
    assert.strictEqual(e.moveDown, true);
  });
});

suite("Steps context menu — the server-rendered menu template (ADR 0103)", () => {
  const html = renderStepsContextMenuHtml();

  test("it is the single hidden #stepsCtxMenu root", () => {
    assert.ok(html.includes('id="stepsCtxMenu"'));
    assert.ok(html.includes("hidden"), "rendered hidden — the script reveals it on right-click");
    assert.ok(html.includes('role="menu"'));
  });

  test("Insert before/after parents each carry the grouped ADD_MENU_CATALOG submenu (ADR 0106)", () => {
    assert.ok(html.includes('data-sub="before"') && html.includes('data-sub="after"'));
    for (const position of ["before", "after"] as const) {
      for (const item of ADD_MENU_CATALOG) {
        assert.ok(
          html.includes(`data-cmd="insert" data-position="${position}" data-item-id="${item.id}"`),
          `${item.id} @ ${position}`,
        );
      }
    }
    for (const item of ADD_MENU_CATALOG) {
      assert.ok(html.includes(`>${item.label}</button>`), item.label);
    }
    // the four group headers + the clause anchor constraint are rendered
    assert.ok(html.includes("ctx-group-label"), "grouped menu");
    assert.ok(html.includes('data-item-id="elif" data-anchor="if_chain"'), "Else If gated to an if chain");
  });

  test("the leaf verbs are Delete / Move up / Move down (Copy/Cut/Paste stay keyboard-served, out of the menu)", () => {
    assert.ok(html.includes('data-cmd="deleteRow"'));
    assert.ok(html.includes('data-cmd="moveUp"'));
    assert.ok(html.includes('data-cmd="moveDown"'));
    assert.ok(!/data-cmd="(copy|cut|paste)/i.test(html), "no copy/cut/paste items in the menu");
  });

  test("the submenu arrow is an HTML entity (the escaper ran)", () => {
    assert.ok(html.includes("&#9656;"), "the submenu arrow is emitted as an entity, not a raw glyph");
  });
});

suite("Steps [blank] placeholder — empty editable inputs hint, saved value stays empty (ADR 0103)", () => {
  test('a recognized editable input carries placeholder="[blank]"', () => {
    const parse = loadFixture("IB_ACME_ADT");
    const vm = buildHandlerViewModels(parse, syntheticSource(parse))[0];
    const html = renderRowHtml(vm.rows[0], vm.handler);
    assert.ok(html.includes('class="edit"'), "precondition: the send `to` field is editable");
    assert.ok(html.includes('placeholder="[blank]"'), "the editable input hints [blank] when empty");
  });

  test("a read-only projection (no handler) has no editable input and no [blank] placeholder", () => {
    const parse = loadFixture("IB_ACME_ADT");
    const vm = buildHandlerViewModels(parse, syntheticSource(parse))[0];
    const html = renderRowHtml(vm.rows[0]); // read-only caller
    assert.ok(!html.includes('class="edit"'));
    assert.ok(!html.includes('placeholder="[blank]"'), "no placeholder on a disabled read-only field");
  });
});

suite("Steps v2 — structural ops force a re-projection (never a queued param coalesce)", () => {
  test("opForcesReprojection: structural ops yes; set_params no", () => {
    assert.strictEqual(opForcesReprojection("delete_row"), true);
    assert.strictEqual(opForcesReprojection("insert_row"), true);
    assert.strictEqual(opForcesReprojection("move_row"), true);
    assert.strictEqual(opForcesReprojection("paste_block"), true);
    assert.strictEqual(opForcesReprojection("set_params"), false);
    // ADR 0106 added the template / insert_clause / insert_comment / insert_code_lookup inserts.
    assert.strictEqual(opForcesReprojection("template"), true);
    assert.strictEqual(opForcesReprojection("insert_code_lookup"), true);
    assert.deepStrictEqual(
      [...STRUCTURAL_OPS].sort(),
      [
        "delete_row",
        "insert_clause",
        "insert_code_lookup",
        "insert_comment",
        "insert_row",
        "move_row",
        "paste_block",
        "template",
      ],
    );
  });

  test("a structural request is NOT a coalescable param EditMessage (distinct queue key shape)", () => {
    // The param queue coalesces EditMessages by `${handler} ${lineStart} ${lineEnd} ${name}`; a
    // structural request has no `name`, so it can never collide with / be dropped by that queue — it
    // rides the separate (single-slot + re-project) path. Assert the shapes are disjoint.
    const del = buildDeleteRequest({ command: "deleteRow", handler: "h", lineStart: 7, lineEnd: 7 });
    assert.ok(!("name" in del), "a delete spec carries no param name to coalesce on");
    assert.strictEqual(del.op, "delete_row");
    assert.ok(opForcesReprojection(del.op), "delete forces a re-projection, not a queue coalesce");
  });
});

suite("Steps v2 — structural affordances appear ONLY on recognized rows", () => {
  function vmOf(row: LensRow, source: string): RowViewModel {
    return buildHandlerViewModels(
      { module: "m", handlers: [{ handler: "h", module: "m", def_line: 1, rows: [row] }] },
      source,
    )[0].rows[0];
  }
  const SRC = "def h(msg):\n    x\n    y\n    z\n";

  test("a recognized (action) row renders move/delete buttons with its coordinates (no per-row ＋)", () => {
    const action: LensRow = {
      kind: "action",
      action: "copy_field",
      params: { src: "PID-5.1", dst: "NK1-2.1" },
      literal_params: ["src", "dst"],
      line_start: 2,
      line_end: 2,
      nesting: 0,
    };
    const html = renderRowHtml(vmOf(action, SRC), "h");
    assert.ok(html.includes('class="rowop"'), "recognized rows carry structural buttons");
    assert.ok(html.includes('data-op="moveUp"') && html.includes('data-op="moveDown"'), "move up/down");
    assert.ok(html.includes('data-op="deleteRow"'), "delete");
    // The per-row ＋ (add-step-after) was REPLACED by the top-of-lens insert toolbar — it is gone.
    assert.ok(!html.includes('data-op="addAfter"'), "no per-row add button (superseded by the toolbar Add)");
    assert.ok(html.includes('data-line-start="2"') && html.includes('data-line-end="2"'), "coords");
    assert.ok(html.includes('data-handler="h"'), "handler scope");
    // The same recognized-row set is a drag SOURCE for the reorder, and carries its nesting depth so the
    // client can pre-filter a cross-suite drop (ADR 0076 drag-to-target).
    assert.ok(html.includes('draggable="true"'), "recognized rows are draggable");
    assert.ok(html.includes('data-nesting="0"'), "the row carries its nesting depth");
  });

  test("every row carries its selection anchor (handler/lines/expect-src/kind) + tabindex on the <li>", () => {
    const action: LensRow = {
      kind: "action",
      action: "set_field",
      params: { path: "MSH-3", value: "MEFOR" },
      literal_params: ["path", "value"],
      line_start: 2,
      line_end: 2,
      nesting: 0,
    };
    const html = renderRowHtml(vmOf(action, SRC), "h");
    assert.ok(html.includes('tabindex="0"'), "the row is keyboard-focusable / selectable");
    assert.ok(html.includes('data-kind="action"'), "the row carries its kind (drives insert position)");
    assert.ok(html.includes('data-handler="h"') && html.includes('data-line-start="2"'), "anchor coords");
  });

  test("a send row is recognized → carries structural buttons", () => {
    const send: LensRow = { kind: "send", outbounds: ["OB_A"], line_start: 2, line_end: 2, nesting: 0 };
    assert.ok(renderRowHtml(vmOf(send, SRC), "h").includes('class="rowop"'));
  });

  test("a code row carries NO structural buttons and stays read-only (but IS marked draggable to answer a move attempt)", () => {
    const code: LensRow = { kind: "code", line_start: 2, line_end: 2, nesting: 0 };
    const html = renderRowHtml(vmOf(code, SRC), "h");
    assert.ok(!html.includes('class="rowop"'), "code row has no move/delete buttons");
    // It carries draggable="true" ONLY so the page script can intercept a drag attempt and show the
    // "edit it in the code editor" message — the drag is cancelled on dragstart and it is never a drop target.
    assert.ok(html.includes('draggable="true"'), "code row is marked draggable to catch a move attempt");
    assert.ok(html.includes('data-kind="code"'), "the code kind lets the page script recognize + lock it");
  });

  test("an if/for control row is MOVABLE — ↑/↓ + draggable, but no delete (ADR 0089 block-move)", () => {
    const control: LensRow = {
      kind: "control",
      control: "if",
      test_src: "msg['A']",
      recognized: true,
      line_start: 2,
      line_end: 2,
      nesting: 0,
    };
    const html = renderRowHtml(vmOf(control, SRC), "h");
    // The header row moves the WHOLE if/for block as a unit — so it gets ↑/↓ + is a drag source...
    assert.ok(
      html.includes('data-op="moveUp"') && html.includes('data-op="moveDown"'),
      "↑/↓ reorder the whole block",
    );
    assert.ok(html.includes('draggable="true"'), "the block is a drag source");
    // ...but NOT delete: a control block is read-only (not template-regenerable, ADR 0076 §5).
    assert.ok(!html.includes('data-op="deleteRow"'), "no delete on a control block");
  });

  test("an elif/else control row is NOT movable (part of its if, not an independent block)", () => {
    for (const branch of ["elif", "else"] as const) {
      const control: LensRow = {
        kind: "control",
        control: branch,
        test_src: null,
        recognized: true,
        line_start: 2,
        line_end: 2,
        nesting: 0,
      };
      const html = renderRowHtml(vmOf(control, SRC), "h");
      assert.ok(!html.includes('class="rowop"'), `${branch} has no reorder buttons`);
      assert.ok(!html.includes('draggable="true"'), `${branch} is not a drag source`);
    }
  });

  test("isRowMovable: action/lookup/send + if/for controls yes; code + elif/else no", () => {
    const row = (over: Partial<LensRow>): LensRow =>
      ({ kind: "action", line_start: 1, line_end: 1, nesting: 0, ...over }) as LensRow;
    assert.ok(isRowMovable(row({ kind: "action" })));
    assert.ok(isRowMovable(row({ kind: "lookup", call: "db_lookup" })));
    assert.ok(isRowMovable(row({ kind: "send", outbounds: ["X"] })));
    assert.ok(isRowMovable(row({ kind: "control", control: "if" })), "a whole if block moves");
    assert.ok(isRowMovable(row({ kind: "control", control: "for" })), "a whole for block moves");
    assert.ok(!isRowMovable(row({ kind: "code" })), "code is the degradation catch-all");
    assert.ok(!isRowMovable(row({ kind: "control", control: "elif" })), "elif is part of its if");
    assert.ok(!isRowMovable(row({ kind: "control", control: "else" })), "else is part of its if");
  });

  test("renderRowHtml emits data-suite (siblings grouping) + movable folds onto the view-model", () => {
    const action: LensRow = {
      kind: "action",
      action: "set_field",
      params: { path: "A", value: "B" },
      literal_params: ["path", "value"],
      line_start: 2,
      line_end: 2,
      nesting: 0,
      suite: "5",
    };
    const vm = vmOf(action, SRC);
    assert.strictEqual(vm.suite, "5");
    assert.strictEqual(vm.movable, true);
    assert.ok(renderRowHtml(vm, "h").includes('data-suite="5"'), "the row carries its suite id");
  });

  test("the read-only caller (no handler scope) shows no structural buttons", () => {
    const action: LensRow = {
      kind: "action",
      action: "copy_field",
      params: { src: "A", dst: "B" },
      line_start: 2,
      line_end: 2,
      nesting: 0,
    };
    assert.ok(!renderRowHtml(vmOf(action, SRC)).includes('class="rowop"'), "no handler → no buttons");
  });
});

// ---- cross-suite drag-and-drop: the pure drop resolver (source of truth the inline script mirrors) ----

suite("Steps cross-suite — canDropRow / resolveDrop / scopeLabel (the pure drop resolver)", () => {
  // A nested handler's flat row list: an if BLOCK (header @6, body A @7) + a def-level leaf B @8 + return @9.
  const ctx = (over: Partial<RowDropContext>): RowDropContext => ({
    handler: "h",
    lineStart: 1,
    lineEnd: 1,
    nesting: 0,
    suite: "5", // def body suite = the def line
    kind: "action",
    draggable: true,
    isControlHeader: false,
    ...over,
  });
  const ifHeader = ctx({
    lineStart: 6,
    lineEnd: 6,
    nesting: 0,
    suite: "5",
    kind: "control",
    isControlHeader: true,
  });
  const bodyA = ctx({ lineStart: 7, lineEnd: 7, nesting: 1, suite: "6" }); // suite id === header line
  const leafB = ctx({ lineStart: 8, lineEnd: 8, nesting: 0, suite: "5" });
  const send = ctx({ lineStart: 9, lineEnd: 9, nesting: 0, suite: "5", kind: "send" });
  const ROWS: RowDropContext[] = [ifHeader, bodyA, leafB, send];

  test("canDropRow: widened — same handler, not self, target draggable, not into own span (NO same-suite)", () => {
    // A def-level leaf B onto the if-BODY row A: different suites, but allowed now (the cross-suite move).
    assert.strictEqual(canDropRow(leafB, bodyA), true, "cross-suite drop is allowed");
    assert.strictEqual(canDropRow(leafB, leafB), false, "not onto itself");
    // A non-draggable target (a code / elif row) is refused.
    assert.strictEqual(canDropRow(leafB, ctx({ lineStart: 3, draggable: false })), false);
    // A different handler is refused.
    assert.strictEqual(canDropRow(leafB, ctx({ lineStart: 3, handler: "other" })), false);
    // A block cannot be dropped into its OWN span: drag the whole if block [6, 7] onto its body row A @7.
    const block = ctx({ lineStart: 6, lineEnd: 7, kind: "control", isControlHeader: true, suite: "5" });
    assert.strictEqual(canDropRow(block, bodyA), false, "a block can't be dropped into its own body");
  });

  test("resolveDrop leaf: pointer half picks before/after; anchor = target, suite/depth = target's", () => {
    const before = resolveDrop(leafB, bodyA, 0.2, ROWS);
    assert.deepStrictEqual(before, {
      anchorLineStart: 7,
      anchorLineEnd: 7,
      toPosition: "before",
      toSuite: "6",
      landingDepth: 1,
    });
    const after = resolveDrop(leafB, bodyA, 0.8, ROWS);
    assert.strictEqual(after?.toPosition, "after");
    assert.strictEqual(after?.toSuite, "6");
    assert.strictEqual(after?.landingDepth, 1);
  });

  test("resolveDrop leaf: a send/return target clamps to 'before' (a block never lands after the return)", () => {
    const res = resolveDrop(leafB, send, 0.95, ROWS); // bottom half, but a send clamps
    assert.strictEqual(res?.toPosition, "before");
    assert.strictEqual(res?.landingDepth, 0);
  });

  test("resolveDrop control-header TOP third → before the block at the OUTER level", () => {
    const res = resolveDrop(leafB, ifHeader, 0.1, ROWS);
    assert.deepStrictEqual(res, {
      anchorLineStart: 6,
      anchorLineEnd: 6,
      toPosition: "before",
      toSuite: "5", // the header's OWN (outer) suite
      landingDepth: 0,
    });
  });

  test("resolveDrop control-header MIDDLE third → INTO the body as its first statement (one level deeper)", () => {
    const res = resolveDrop(leafB, ifHeader, 0.5, ROWS);
    assert.deepStrictEqual(res, {
      anchorLineStart: 7, // the body's first row (suite === header line "6")
      anchorLineEnd: 7,
      toPosition: "before",
      toSuite: "6", // the body suite id
      landingDepth: 1, // header.nesting + 1
    });
  });

  test("resolveDrop control-header BOTTOM third → after the block at the OUTER level", () => {
    const res = resolveDrop(leafB, ifHeader, 0.9, ROWS);
    assert.deepStrictEqual(res, {
      anchorLineStart: 6,
      anchorLineEnd: 6,
      toPosition: "after",
      toSuite: "5",
      landingDepth: 0,
    });
  });

  test("resolveDrop control-header MIDDLE with an EMPTY body → null (no first row to anchor)", () => {
    // A header whose body has no row in ROWS (suite "6" absent) — the into-body gesture has no anchor.
    const lonelyHeader = ctx({
      lineStart: 6,
      lineEnd: 6,
      kind: "control",
      isControlHeader: true,
      suite: "5",
    });
    assert.strictEqual(resolveDrop(leafB, lonelyHeader, 0.5, [lonelyHeader, leafB, send]), null);
  });

  test("resolveDrop: not-into-own-span and cross-handler both → null", () => {
    const block = ctx({ lineStart: 6, lineEnd: 7, kind: "control", isControlHeader: true, suite: "5" });
    assert.strictEqual(resolveDrop(block, bodyA, 0.5, ROWS), null, "into own span → null");
    const otherHandlerTarget = ctx({ lineStart: 8, handler: "other" });
    assert.strictEqual(resolveDrop(leafB, otherHandlerTarget, 0.5, ROWS), null, "cross-handler → null");
  });

  test("scopeLabel: depth 0 → 'top level'; else 'inside <enclosing header title>' with a terse fallback", () => {
    const headers = [
      { lineStart: 6, title: "For each OBX segment" },
      { lineStart: 12, title: "If ADT" },
    ];
    assert.strictEqual(scopeLabel(0, "5", headers), "top level");
    assert.strictEqual(scopeLabel(1, "6", headers), "inside For each OBX segment");
    assert.strictEqual(scopeLabel(2, "12", headers), "inside If ADT");
    // A suite id with no matching header row → the terse fallback (defensive; never happens in practice).
    assert.strictEqual(scopeLabel(1, "999", headers), "inside this block");
  });
});

// ---- cross-suite drag-and-drop: the insertion-bar anchor (the DROP indicator's vertical position) -------

suite("Steps cross-suite — insertionBarAnchor (where the insertion bar lands)", () => {
  // A handler whose for-loop CONTAINS a nested if/else, so the tri-zone "after the whole block" gesture must
  // resolve the bar to the block's VISUAL bottom — below every body row — and NOT the header/body boundary
  // (which reads as the middle-third "into body" bar). Flat row list in DOCUMENT order:
  //   6  leaf X (the drag source)           nesting 0, suite "5"
  //   7  for header                         nesting 0, suite "5", control "for"
  //   8    a (for body)                     nesting 1, suite "7"
  //   9    if header                        nesting 1, suite "7", control "if"
  //   10     b (if body)                    nesting 2, suite "9"
  //   11   else header (continuation)       nesting 1, suite "7", control "else"
  //   12     c (else body)                  nesting 2, suite "11"
  //   13  return (send)                     nesting 0, suite "5"
  const ctx = (over: Partial<RowDropContext>): RowDropContext => ({
    handler: "h",
    lineStart: 1,
    lineEnd: 1,
    nesting: 0,
    suite: "5",
    kind: "action",
    draggable: true,
    isControlHeader: false,
    ...over,
  });
  const dragX = ctx({ lineStart: 6, lineEnd: 6, nesting: 0, suite: "5" });
  const forHeader = ctx({
    lineStart: 7,
    lineEnd: 7,
    nesting: 0,
    suite: "5",
    kind: "control",
    isControlHeader: true,
    control: "for",
  });
  const aBody = ctx({ lineStart: 8, lineEnd: 8, nesting: 1, suite: "7" });
  const ifHeader = ctx({
    lineStart: 9,
    lineEnd: 9,
    nesting: 1,
    suite: "7",
    kind: "control",
    isControlHeader: true,
    control: "if",
  });
  const bBody = ctx({ lineStart: 10, lineEnd: 10, nesting: 2, suite: "9" });
  // elif/else are NOT draggable and NOT drop targets, but they ARE block continuations the bar walk crosses.
  const elseHeader = ctx({
    lineStart: 11,
    lineEnd: 11,
    nesting: 1,
    suite: "7",
    kind: "control",
    isControlHeader: false,
    draggable: false,
    control: "else",
  });
  const cBody = ctx({ lineStart: 12, lineEnd: 12, nesting: 2, suite: "11" });
  const ret = ctx({ lineStart: 13, lineEnd: 13, nesting: 0, suite: "5", kind: "send" });
  const ROWS: RowDropContext[] = [dragX, forHeader, aBody, ifHeader, bBody, elseHeader, cBody, ret];

  test("control-header 'after whole block' anchors to the block's VISUAL BOTTOM, not the header", () => {
    const res = resolveDrop(dragX, forHeader, 0.9, ROWS)!;
    assert.strictEqual(res.toPosition, "after"); // bottom-third gesture
    // The for block spans rows 7..12 (its body includes the nested if/else); the visual bottom is else-body @12.
    assert.deepStrictEqual(insertionBarAnchor(res, ROWS), { anchorLineStart: 12, edge: "bottom" });
  });

  test("the walk crosses an else CONTINUATION (a naive nesting-only walk would stop at the if body)", () => {
    // Drop 'after' the INNER if header: its block is 9..12; without the elif/else continuation rule the walk
    // would stop at the if body @10 and draw the bar ABOVE the else, promising the wrong scope.
    const res = resolveDrop(dragX, ifHeader, 0.9, ROWS)!;
    assert.deepStrictEqual(insertionBarAnchor(res, ROWS), { anchorLineStart: 12, edge: "bottom" });
  });

  test("the 'into body' (middle) and 'after block' (bottom) bars land at DIFFERENT rows — the tri-zone split", () => {
    const intoBody = resolveDrop(dragX, forHeader, 0.5, ROWS)!;
    const afterBlock = resolveDrop(dragX, forHeader, 0.9, ROWS)!;
    // Into-body → the first body row's TOP (@8); after-block → the block's bottom (@12). Distinct positions,
    // so the classic for-header ambiguity (constraint 5) is now visually unambiguous.
    assert.deepStrictEqual(insertionBarAnchor(intoBody, ROWS), { anchorLineStart: 8, edge: "top" });
    assert.deepStrictEqual(insertionBarAnchor(afterBlock, ROWS), { anchorLineStart: 12, edge: "bottom" });
  });

  test("control-header 'before' (top third) anchors to the header's TOP edge", () => {
    const res = resolveDrop(dragX, forHeader, 0.1, ROWS)!;
    assert.deepStrictEqual(insertionBarAnchor(res, ROWS), { anchorLineStart: 7, edge: "top" });
  });

  test("a leaf 'after' anchors to the leaf's own bottom edge (no block walk)", () => {
    const res = resolveDrop(dragX, aBody, 0.8, ROWS)!;
    assert.deepStrictEqual(insertionBarAnchor(res, ROWS), { anchorLineStart: 8, edge: "bottom" });
  });

  test("a leaf 'before' anchors to the leaf's own top edge", () => {
    const res = resolveDrop(dragX, aBody, 0.2, ROWS)!;
    assert.deepStrictEqual(insertionBarAnchor(res, ROWS), { anchorLineStart: 8, edge: "top" });
  });

  test("after a for header with NO body rows following → falls back to the header itself", () => {
    // Defensive: an (unusual) empty-bodied header at the end — the walk finds no deeper/continuation row, so
    // the anchor stays the header's own bottom (never throws, never picks an unrelated following row).
    const lonelyFor = ctx({
      lineStart: 7,
      lineEnd: 7,
      nesting: 0,
      suite: "5",
      kind: "control",
      isControlHeader: true,
      control: "for",
    });
    const rows = [dragX, lonelyFor];
    const res = resolveDrop(dragX, lonelyFor, 0.9, rows)!;
    assert.deepStrictEqual(insertionBarAnchor(res, rows), { anchorLineStart: 7, edge: "bottom" });
  });
});

suite("Steps cross-suite — walkMove (↑/↓ as a stepwise cross-suite drag: 'walk into blocks')", () => {
  const ctx = (over: Partial<RowDropContext>): RowDropContext => ({
    handler: "h",
    lineStart: 0,
    lineEnd: 0,
    nesting: 0,
    suite: "4", // def body suite
    kind: "action",
    draggable: true,
    isControlHeader: false,
    ...over,
  });

  // Mirrors the real `lens parse` shape (verified against a probe):
  //   A(5)   if(6){ I(7) for(8){ F(9) } } elif(10){ L(11) } else(12){ U(13) }   D(14)   return(15)
  // elif/else are CONTINUATIONS (suite '4', NOT draggable); each header opens its own body suite.
  const A = ctx({ lineStart: 5, lineEnd: 5 });
  const ifH = ctx({ lineStart: 6, lineEnd: 6, kind: "control", control: "if", isControlHeader: true });
  const I = ctx({ lineStart: 7, lineEnd: 7, nesting: 1, suite: "6" });
  const forH = ctx({ lineStart: 8, lineEnd: 8, nesting: 1, suite: "6", kind: "control", control: "for", isControlHeader: true });
  const F = ctx({ lineStart: 9, lineEnd: 9, nesting: 2, suite: "8" });
  const elifH = ctx({ lineStart: 10, lineEnd: 10, kind: "control", control: "elif", draggable: false });
  const L = ctx({ lineStart: 11, lineEnd: 11, nesting: 1, suite: "10" });
  const elseH = ctx({ lineStart: 12, lineEnd: 12, kind: "control", control: "else", draggable: false });
  const U = ctx({ lineStart: 13, lineEnd: 13, nesting: 1, suite: "12" });
  const D = ctx({ lineStart: 14, lineEnd: 14 });
  const ret = ctx({ lineStart: 15, lineEnd: 15, kind: "send" });
  const ROWS: RowDropContext[] = [A, ifH, I, forH, F, elifH, L, elseH, U, D, ret];

  test("↓ on a top-level step above a block ENTERS the block (first statement of the if body)", () => {
    assert.deepStrictEqual(walkMove(ROWS, 5, "down"), {
      anchorLineStart: 7,
      anchorLineEnd: 7,
      toPosition: "before",
      toSuite: "6",
      landingDepth: 1,
    });
  });

  test("↑ on the FIRST step of the handler → null (already at the top)", () => {
    assert.strictEqual(walkMove(ROWS, 5, "up"), null);
  });

  test("↑ on a step INSIDE the if body steps OUT to the outer level (after the step above the if)", () => {
    assert.deepStrictEqual(walkMove(ROWS, 7, "up"), {
      anchorLineStart: 5,
      anchorLineEnd: 5,
      toPosition: "after",
      toSuite: "4",
      landingDepth: 0,
    });
  });

  test("↓ on a step in the if body ENTERS the nested for body (one level deeper)", () => {
    assert.deepStrictEqual(walkMove(ROWS, 7, "down"), {
      anchorLineStart: 9,
      anchorLineEnd: 9,
      toPosition: "before",
      toSuite: "8",
      landingDepth: 2,
    });
  });

  test("a whole if/elif/else BLOCK moves as one unit: ↓ jumps it below the next top-level step", () => {
    assert.deepStrictEqual(walkMove(ROWS, 6, "down"), {
      anchorLineStart: 14,
      anchorLineEnd: 14,
      toPosition: "after",
      toSuite: "4",
      landingDepth: 0,
    });
    assert.deepStrictEqual(walkMove(ROWS, 6, "up"), {
      anchorLineStart: 5,
      anchorLineEnd: 5,
      toPosition: "before",
      toSuite: "4",
      landingDepth: 0,
    });
  });

  test("↑ on the last top-level step ENTERS the else body (last statement) from below", () => {
    assert.deepStrictEqual(walkMove(ROWS, 14, "up"), {
      anchorLineStart: 13,
      anchorLineEnd: 13,
      toPosition: "after",
      toSuite: "12",
      landingDepth: 1,
    });
  });

  test("↓ on the last movable step (just above the return) → null (a block never lands after the return)", () => {
    assert.strictEqual(walkMove(ROWS, 14, "down"), null);
  });

  test("the walkMove result maps 1:1 to a verified drag-to-target move_row spec", () => {
    const res = walkMove(ROWS, 5, "down")!;
    assert.deepStrictEqual(
      buildMoveToRequest({
        command: "moveTo",
        handler: "h",
        lineStart: 5,
        lineEnd: 5,
        toLineStart: res.anchorLineStart,
        toLineEnd: res.anchorLineEnd,
        toPosition: res.toPosition,
        toSuite: res.toSuite,
      }),
      {
        handler: "h",
        line_start: 5,
        line_end: 5,
        op: "move_row",
        to_line_start: 7,
        to_line_end: 7,
        to_position: "before",
        to_suite: "6",
      },
    );
  });

  test("the SOLE statement of a loop body can't be walked out (would empty the suite) → null both ways", () => {
    const a2 = ctx({ lineStart: 6, lineEnd: 6, suite: "5" });
    const for2 = ctx({ lineStart: 7, lineEnd: 7, suite: "5", kind: "control", control: "for", isControlHeader: true });
    const x2 = ctx({ lineStart: 8, lineEnd: 8, nesting: 1, suite: "7" }); // sole child of the for body
    const ret2 = ctx({ lineStart: 9, lineEnd: 9, suite: "5", kind: "send" });
    const ROWS2: RowDropContext[] = [a2, for2, x2, ret2];
    assert.strictEqual(walkMove(ROWS2, 8, "up"), null);
    assert.strictEqual(walkMove(ROWS2, 8, "down"), null);
    // but the (non-empty) for block itself still walks up above its sibling:
    assert.deepStrictEqual(walkMove(ROWS2, 7, "up"), {
      anchorLineStart: 6,
      anchorLineEnd: 6,
      toPosition: "before",
      toSuite: "5",
      landingDepth: 0,
    });
  });

  test("a non-existent / non-draggable start line → null (defensive)", () => {
    assert.strictEqual(walkMove(ROWS, 999, "down"), null);
    assert.strictEqual(walkMove(ROWS, 10, "down"), null); // elif header is a continuation, not draggable
  });
});

// ---- Steps block copy / cut / paste: extent + capture + clipboard + paste-request mapping -------------

suite("Steps block clipboard — blockExtent / captureBlock / blockLabel / buildPasteRequest", () => {
  const row = (over: Partial<BlockCaptureRow>): BlockCaptureRow => ({
    handler: "h",
    lineStart: 0,
    lineEnd: 0,
    nesting: 0,
    suite: "4", // def body suite
    kind: "action",
    draggable: true,
    isControlHeader: false,
    expectSrc: "",
    ...over,
  });
  // A(5) if(6){ I(7) } elif(8){ L(9) } else(10){ U(11) } D(12) return(13) — elif/else are continuations.
  const A = row({ lineStart: 5, lineEnd: 5, expectSrc: '    set_field(msg, "A", "1")' });
  const ifH = row({
    lineStart: 6,
    lineEnd: 6,
    kind: "control",
    control: "if",
    isControlHeader: true,
    expectSrc: '    if msg["A"]:',
  });
  const I = row({ lineStart: 7, lineEnd: 7, nesting: 1, suite: "6", expectSrc: '        set_field(msg, "I", "1")' });
  const elifH = row({ lineStart: 8, lineEnd: 8, kind: "control", control: "elif", draggable: false, expectSrc: '    elif msg["B"]:' });
  const L = row({ lineStart: 9, lineEnd: 9, nesting: 1, suite: "8", expectSrc: '        set_field(msg, "L", "1")' });
  const elseH = row({ lineStart: 10, lineEnd: 10, kind: "control", control: "else", draggable: false, expectSrc: "    else:" });
  const U = row({ lineStart: 11, lineEnd: 11, nesting: 1, suite: "10", expectSrc: '        set_field(msg, "U", "1")' });
  const D = row({ lineStart: 12, lineEnd: 12, expectSrc: '    set_field(msg, "D", "1")' });
  const ret = row({ lineStart: 13, lineEnd: 13, kind: "send", expectSrc: '    return Send("OB", msg)' });
  const code = row({ lineStart: 14, lineEnd: 14, kind: "code", expectSrc: "    x = weird(msg)" });
  const ROWS: BlockCaptureRow[] = [A, ifH, I, elifH, L, elseH, U, D, ret];

  test("blockExtent: a leaf is itself; an if header covers its body + elif/else continuations", () => {
    assert.deepStrictEqual(blockExtent(ROWS, 5), { startIndex: 0, endIndex: 0 }); // leaf A
    assert.deepStrictEqual(blockExtent(ROWS, 6), { startIndex: 1, endIndex: 6 }); // if..else body (6..11)
    assert.strictEqual(blockExtent(ROWS, 8), null); // an elif header is a continuation, not draggable
    assert.strictEqual(blockExtent(ROWS, 999), null); // absent
  });

  test("blockExtent is the SAME extent walkMove moves (shared source of truth — cannot diverge)", () => {
    // The whole if block (rows 6..11) is one movable unit for BOTH the arrow walk and a copy/cut capture.
    assert.deepStrictEqual(blockExtent(ROWS, 6), { startIndex: 1, endIndex: 6 });
    assert.ok(walkMove(ROWS, 6, "down"), "the whole if block walks as one unit (same extent)");
  });

  test("captureBlock: a leaf → its expectSrc + coords + kind + nesting", () => {
    assert.deepStrictEqual(captureBlock(ROWS, 5), {
      source: '    set_field(msg, "A", "1")',
      nesting: 0,
      kind: "action",
      lineStart: 5,
      lineEnd: 5,
      lineCount: 1,
    });
  });

  test("captureBlock: an if block → header + body + continuations joined by LF (the buffer slice)", () => {
    const cap = captureBlock(ROWS, 6);
    assert.ok(cap);
    assert.strictEqual(cap!.source, [ifH, I, elifH, L, elseH, U].map((r) => r.expectSrc).join("\n"));
    assert.strictEqual(cap!.kind, "control");
    assert.strictEqual(cap!.lineStart, 6);
    assert.strictEqual(cap!.lineEnd, 11);
    assert.strictEqual(cap!.lineCount, 6);
    assert.strictEqual(cap!.nesting, 0);
  });

  test("captureBlock: a code row → null; a non-draggable (elif) start → null; absent → null", () => {
    const withCode: BlockCaptureRow[] = [...ROWS, code];
    assert.strictEqual(captureBlock(withCode, 14), null); // a Code step is read-only, never copied
    assert.strictEqual(captureBlock(ROWS, 8), null); // elif continuation is not a capturable block
    assert.strictEqual(captureBlock(ROWS, 999), null); // absent start
  });

  test("blockLabel: control → 'the if block' / 'the loop'; leaves → step count", () => {
    assert.strictEqual(blockLabel("control", 4, "if"), "the if block");
    assert.strictEqual(blockLabel("control", 2, "for"), "the loop");
    assert.strictEqual(blockLabel("action", 1), "1 step");
    assert.strictEqual(blockLabel("send", 3), "3 steps");
  });

  test("buildPasteRequest: position from anchor kind (send→before, else after); carries block + expect_src", () => {
    const clip: ClipboardBlock = {
      source: '    set_field(msg, "A", "B")',
      nesting: 0,
      kind: "action",
      lineCount: 1,
      label: "1 step",
    };
    assert.deepStrictEqual(
      buildPasteRequest(
        { handler: "enrich", lineStart: 6, lineEnd: 6, expectSrc: '    copy_field(msg, "A", "B")', kind: "action" },
        clip,
      ),
      {
        handler: "enrich",
        line_start: 6,
        line_end: 6,
        op: "paste_block",
        position: "after",
        block: '    set_field(msg, "A", "B")',
        expect_src: '    copy_field(msg, "A", "B")',
      },
    );
    const beforeReq = buildPasteRequest(
      { handler: "enrich", lineStart: 9, lineEnd: 9, expectSrc: "    return Send(...)", kind: "send" },
      clip,
    );
    assert.strictEqual(beforeReq.position, "before", "a send anchor pastes BEFORE the return");
  });

  test("buildPasteRequest omits expect_src when the anchor has none (byte-identical no-expect payload)", () => {
    const clip: ClipboardBlock = { source: "    x", nesting: 0, kind: "action", lineCount: 1, label: "1 step" };
    const req = buildPasteRequest({ handler: "h", lineStart: 3, lineEnd: 3, kind: "action" }, clip);
    assert.ok(!("expect_src" in req), "no anchor expectSrc → no expect_src key");
    assert.strictEqual(req.op, "paste_block");
    assert.ok(opForcesReprojection(req.op), "paste forces a re-projection (it changes line counts)");
  });

  test("CUT reuses buildDeleteRequest with the selected row's OWN coords (leaf span, or if/for header)", () => {
    // A leaf cut → delete its own [lineStart, lineEnd] span, carrying expect_src (F7).
    assert.deepStrictEqual(
      buildDeleteRequest({
        command: "deleteRow",
        handler: "h",
        lineStart: 7,
        lineEnd: 7,
        expectSrc: '    set_field(msg, "A", "B")',
      }),
      {
        handler: "h",
        line_start: 7,
        line_end: 7,
        op: "delete_row",
        expect_src: '    set_field(msg, "A", "B")',
      },
    );
    // A whole-block cut → the if/for HEADER's own [header, header] span (the engine removes the whole block).
    const block = buildDeleteRequest({
      command: "deleteRow",
      handler: "h",
      lineStart: 6,
      lineEnd: 6,
      expectSrc: '    if msg["A"]:',
    });
    assert.strictEqual(block.line_start, 6);
    assert.strictEqual(block.line_end, 6);
    assert.strictEqual(block.op, "delete_row");
    assert.ok(opForcesReprojection(block.op));
  });
});
