import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

import {
  REDACTED_LIVE_VALUE,
  buildHandlerViewModels,
  buildLensTraceArgs,
  mergeLiveValues,
  renderHandlersHtml,
  renderRowHtml,
  shouldAttachLiveValues,
  shouldFallBackToText,
  traceRowValues,
  type LensParseResult,
  type LiveInlineValue,
  type RowViewModel,
} from "../../stepsModel";
import type { TraceInvocation } from "../../liveDebug";

// Pure (vscode-free) view-model for the read-only Steps view (#222, ADR 0076 phase 2b) —
// exercised node-side against the committed `lens parse --json` fixtures (the CI ide job has no Python,
// so the CLI boundary is stubbed by the canned JSON). Covers: the coverage/order invariant (every
// contract row rendered, in order), kind→row-type mapping, params display, in-place code-row passthrough
// (the §4 degradation ladder), the parse-error→fallback decision, and the redacted-by-default live-value
// merge (the L3 PHI gate — values are NEVER un-redacted here).

const FIXTURE_DIR = path.join(__dirname, "..", "..", "..", "src", "test", "fixtures", "lens");

function loadFixture(name: string): LensParseResult {
  return JSON.parse(fs.readFileSync(path.join(FIXTURE_DIR, `${name}.json`), "utf8")) as LensParseResult;
}

function fixtureNames(): string[] {
  return fs
    .readdirSync(FIXTURE_DIR)
    .filter((f) => f.endsWith(".json"))
    .map((f) => f.replace(/\.json$/, ""));
}

/** A synthetic source with enough lines that every row's [line_start, line_end] can be sliced. */
function syntheticSource(parse: LensParseResult): string {
  let maxLine = 1;
  for (const h of parse.handlers) {
    for (const r of h.rows) {
      maxLine = Math.max(maxLine, r.line_end, h.def_line);
    }
  }
  return Array.from({ length: maxLine }, (_, i) => `line_${i + 1}`).join("\n");
}

suite("stepsModel — coverage/order invariant over the committed fixtures", () => {
  test("every fixture handler renders exactly its contract rows, in order, with line ranges preserved", () => {
    const names = fixtureNames();
    assert.ok(names.length >= 5, "expected the L2 fixtures to be present");
    for (const name of names) {
      const parse = loadFixture(name);
      const vms = buildHandlerViewModels(parse, syntheticSource(parse));
      assert.strictEqual(vms.length, parse.handlers.length, `${name}: handler count`);
      for (let h = 0; h < vms.length; h++) {
        const contract = parse.handlers[h];
        const vm = vms[h];
        assert.strictEqual(vm.handler, contract.handler, `${name}: handler name`);
        assert.strictEqual(vm.rows.length, contract.rows.length, `${name}/${vm.handler}: row count`);
        for (let i = 0; i < vm.rows.length; i++) {
          const row = vm.rows[i];
          const cr = contract.rows[i];
          assert.strictEqual(row.index, i, `${name}/${vm.handler}[${i}]: index == position`);
          assert.strictEqual(row.kind, cr.kind, `${name}/${vm.handler}[${i}]: kind passthrough`);
          assert.strictEqual(row.lineStart, cr.line_start, `${name}/${vm.handler}[${i}]: line_start`);
          assert.strictEqual(row.lineEnd, cr.line_end, `${name}/${vm.handler}[${i}]: line_end`);
          assert.strictEqual(row.nesting, cr.nesting, `${name}/${vm.handler}[${i}]: nesting`);
        }
      }
    }
  });
});

suite("stepsModel — kind → row-type + params display", () => {
  test("control rows carry the test as subtitle; an unrecognized test is badged, a recognized one is not", () => {
    const adt = buildHandlerViewModels(loadFixture("adt"), syntheticSource(loadFixture("adt")))[0];
    const ifRow = adt.rows.find((r) => r.kind === "control");
    assert.ok(ifRow, "adt has a control row");
    assert.strictEqual(ifRow!.title, "If");
    assert.strictEqual(ifRow!.subtitle, 'msg["MSH-9.2"] not in EVENT_LABELS');
    assert.strictEqual(ifRow!.badge, undefined, "a recognized test gets no unrecognized badge");

    const rad = buildHandlerViewModels(
      loadFixture("IB_RADIOLOGY_SR"),
      syntheticSource(loadFixture("IB_RADIOLOGY_SR")),
    )[0];
    const forRow = rad.rows.find((r) => r.kind === "control" && r.title === "For each");
    assert.ok(forRow, "radiology handler has a for-loop control row");
    assert.strictEqual(forRow!.badge, "unrecognized", "an unrecognized for-iter is badged, never hidden");
  });

  test("send rows title as Send with the destination as subtitle + a read-only `to` param", () => {
    const acme = buildHandlerViewModels(
      loadFixture("IB_ACME_ADT"),
      syntheticSource(loadFixture("IB_ACME_ADT")),
    )[0];
    const send = acme.rows.find((r) => r.kind === "send");
    assert.ok(send, "acme handler ends in a send row");
    assert.strictEqual(send!.title, "Send");
    assert.strictEqual(send!.subtitle, "OB_ACME_ADT");
    assert.deepStrictEqual(send!.params, [{ name: "to", value: "OB_ACME_ADT" }]);
  });

  test("action + lookup rows get friendly labels and their params as ordered read-only fields", () => {
    // The sample corpus is send/code/control-only; exercise action/lookup with a handcrafted contract.
    const parse: LensParseResult = {
      module: "x.py",
      handlers: [
        {
          handler: "enrich",
          module: "x.py",
          def_line: 1,
          rows: [
            {
              kind: "action",
              action: "copy_field",
              params: { src: "PID-5.1", dst: "NK1-2.1" },
              line_start: 2,
              line_end: 2,
              nesting: 0,
            },
            {
              kind: "lookup",
              call: "db_lookup",
              assign_to: "row",
              params: { connection: "DB_MPI", statement: "select 1", params: ["a", "b"] },
              line_start: 3,
              line_end: 3,
              nesting: 0,
            },
          ],
        },
      ],
    };
    const vm = buildHandlerViewModels(parse, "l1\nl2\nl3")[0];
    const [action, lookup] = vm.rows;
    assert.strictEqual(action.title, "Copy Field");
    assert.deepStrictEqual(action.params, [
      { name: "src", value: "PID-5.1" },
      { name: "dst", value: "NK1-2.1" },
    ]);
    assert.strictEqual(lookup.title, "DB Lookup");
    assert.strictEqual(lookup.subtitle, "→ row", "a lookup's assignment target renders as its subtitle");
    assert.deepStrictEqual(lookup.params, [
      { name: "connection", value: "DB_MPI" },
      { name: "statement", value: "select 1" },
      { name: "params", value: "a, b" },
    ]);
  });
});

suite("stepsModel — code-row passthrough (the §4 degradation ladder)", () => {
  test("a code row carries the verbatim source of its line range, never hidden", () => {
    const parse: LensParseResult = {
      module: "x.py",
      handlers: [
        {
          handler: "h",
          module: "x.py",
          def_line: 1,
          rows: [{ kind: "code", line_start: 2, line_end: 3, nesting: 1 }],
        },
      ],
    };
    const source = ["def h(msg):", "    x = weird(msg)  # unrecognized", "    y = x + 1", "    return None"].join(
      "\n",
    );
    const vm = buildHandlerViewModels(parse, source)[0];
    assert.strictEqual(vm.rows.length, 1);
    assert.strictEqual(vm.rows[0].kind, "code");
    assert.strictEqual(vm.rows[0].code, "    x = weird(msg)  # unrecognized\n    y = x + 1");
  });
});

suite("stepsModel — parse-error → text-editor fallback decision", () => {
  test("a CLI/parse error falls back to text with the error in the notice", () => {
    const d = shouldFallBackToText(null, "x.py: cannot parse (invalid syntax at line 3)");
    assert.strictEqual(d.fallback, true);
    assert.ok(d.reason && d.reason.includes("cannot parse"), "notice surfaces the parse error");
  });

  test("a parsed module with no @handler falls back (Handlers only in v1)", () => {
    const d = shouldFallBackToText({ module: "x.py", handlers: [] }, null);
    assert.strictEqual(d.fallback, true);
  });

  test("a parsed module with at least one handler renders (no fallback)", () => {
    const d = shouldFallBackToText(loadFixture("IB_ACME_ADT"), null);
    assert.strictEqual(d.fallback, false);
    assert.strictEqual(d.reason, undefined);
  });

  test("a null parse with no error still falls back rather than showing a blank lens", () => {
    assert.strictEqual(shouldFallBackToText(null, null).fallback, true);
  });
});

suite("stepsModel — redacted-by-default live-value merge (PHI gate)", () => {
  const rows: RowViewModel[] = [
    { index: 0, kind: "action", nesting: 0, lineStart: 2, lineEnd: 2, title: "A", params: [] },
    { index: 1, kind: "send", nesting: 0, lineStart: 5, lineEnd: 6, title: "Send", params: [] },
  ];

  test("a redacted inline value (the default) attaches to the row whose line range contains it", () => {
    const rowsCopy = rows.map((r) => ({ ...r }));
    // liveDebug emits 0-based lines; the value on 0-based line 1 is source line 2 → the action row.
    const inline: LiveInlineValue[] = [{ line: 1, after: REDACTED_LIVE_VALUE, kind: "value" }];
    mergeLiveValues(rowsCopy, inline);
    assert.strictEqual(rowsCopy[0].liveValue, REDACTED_LIVE_VALUE, "attached, and redacted by default");
    assert.strictEqual(rowsCopy[1].liveValue, undefined, "the other row gets nothing");
    // The default annotation must be the redacted placeholder — never a real value.
    assert.ok(!/[A-Za-z0-9]{2,}/.test(REDACTED_LIVE_VALUE), "the default placeholder carries no value text");
  });

  test("multiple values within one multi-line row are joined; out-of-range values attach to nothing", () => {
    const rowsCopy = rows.map((r) => ({ ...r }));
    const inline: LiveInlineValue[] = [
      { line: 4, after: REDACTED_LIVE_VALUE, kind: "value" }, // source line 5 → send row
      { line: 5, after: REDACTED_LIVE_VALUE, kind: "value" }, // source line 6 → send row
      { line: 20, after: REDACTED_LIVE_VALUE, kind: "value" }, // beyond every row → dropped
    ];
    mergeLiveValues(rowsCopy, inline);
    assert.strictEqual(rowsCopy[0].liveValue, undefined);
    assert.strictEqual(
      rowsCopy[1].liveValue,
      `${REDACTED_LIVE_VALUE}  ·  ${REDACTED_LIVE_VALUE}`,
      "both in-range annotations joined",
    );
  });
});

suite("stepsModel — HTML rendering safety", () => {
  test("renderHandlersHtml runs over every fixture without throwing", () => {
    for (const name of fixtureNames()) {
      const parse = loadFixture(name);
      const html = renderHandlersHtml(buildHandlerViewModels(parse, syntheticSource(parse)));
      assert.ok(html.length > 0, `${name}: produced HTML`);
    }
  });

  test("HL7-derived param values are HTML-escaped (no attribute/markup break-out)", () => {
    const row: RowViewModel = {
      index: 0,
      kind: "action",
      nesting: 0,
      lineStart: 1,
      lineEnd: 1,
      title: "Set Field",
      params: [{ name: "value", value: '"><script>alert(1)</script>' }],
    };
    const html = renderRowHtml(row);
    assert.ok(!html.includes("<script>"), "the injected script tag is escaped");
    assert.ok(html.includes("&lt;script&gt;"), "escaped form is present");
  });
});

// ---- BACKLOG #225: live per-row values from a second traced dry-run (ADR 0076 addendum / ADR 0072) --
// Exercised node-side against CANNED `dryrun --trace json` invocations (the CI ide job has no Python, and
// these values are SYNTHETIC). Covers: trace→row value mapping by line, redacted-by-default (no reveal ⇒
// placeholder), a no-sample/empty trace degrading gracefully, and that the default argv never carries
// `--show-phi`. `traceRowValues`/`buildLensTraceArgs` are pure (the vscode-coupled shell + file-filter
// live in the provider); `TraceInvocation` is imported as a TYPE only, so this stays vscode-free.

/** A canned traced invocation (SYNTHETIC values only — never real PHI). */
function inv(over: Partial<TraceInvocation>): TraceInvocation {
  return {
    kind: "handler",
    name: "enrich",
    module: "x.py",
    file: "/cfg/x.py",
    def_line: 1,
    events: [],
    disposition: "PROCESSED",
    sends: [],
    routed_to: [],
    annotations: [],
    ...over,
  };
}

// One invocation that assigns a local on source line 3 and writes msg["PID-5.1"] on source line 6.
const PRODUCING = inv({
  events: [
    { line: 3, event: "line", assigned: { mrn: "12345" } },
    { line: 6, event: "line", writes: [{ path: "PID-5.1", value: "SMITH" }] },
  ],
});

// Two rows the values should map onto: an action on line 3, a multi-line send on lines 5–6.
function twoRows(): RowViewModel[] {
  return [
    { index: 0, kind: "action", nesting: 0, lineStart: 3, lineEnd: 3, title: "A", params: [] },
    { index: 1, kind: "send", nesting: 0, lineStart: 5, lineEnd: 6, title: "Send", params: [] },
  ];
}

suite("stepsModel — buildLensTraceArgs never requests PHI (the lens's redacted-by-default gate)", () => {
  test("the default trace argv is `dryrun … --trace json` with NO --show-phi", () => {
    const args = buildLensTraceArgs("samples/config", "/synthetic/adt_a01.hl7");
    assert.deepStrictEqual(args, [
      "dryrun",
      "--config",
      "samples/config",
      "--messages",
      "/synthetic/adt_a01.hl7",
      "--trace",
      "json",
    ]);
    assert.ok(!args.includes("--show-phi"), "the lens must NEVER pass --show-phi (PHI stays redacted)");
  });
});

suite("stepsModel — traceRowValues folds a traced dry-run onto rows (redacted by default)", () => {
  test("redacted by default (reveal off): each executed line is the ▸ ⋯ placeholder, no real value", () => {
    const off = traceRowValues([PRODUCING], false);
    assert.strictEqual(off.length, 2);
    for (const iv of off) {
      assert.strictEqual(iv.kind, "value");
      assert.ok(iv.after.includes("⋯"), `expected placeholder, got: ${iv.after}`);
      assert.ok(!/12345|SMITH/.test(iv.after), `no real value leaks: ${iv.after}`);
    }
    // Merged onto rows, the DEFAULT annotation is redacted on the row that contains the line.
    const rows = twoRows();
    mergeLiveValues(rows, off);
    assert.ok(rows[0].liveValue && !/12345/.test(rows[0].liveValue), rows[0].liveValue);
    assert.ok(rows[1].liveValue && !/SMITH/.test(rows[1].liveValue), rows[1].liveValue);
  });

  test("trace → row value mapping: the right (revealed) value lands on the right row by line containment", () => {
    // reveal=true only to prove the mapping mechanics with distinguishable synthetic values — the PROVIDER
    // always calls with reveal off and never passes --show-phi, so this path is preview/test-only.
    const on = traceRowValues([PRODUCING], true);
    const rows = twoRows();
    mergeLiveValues(rows, on);
    // local `mrn` produced on line 3 → the action row (line 3); write on line 6 → the send row (lines 5–6).
    // A single captured item on a line renders bare (`▸ "SMITH"`), mirroring liveDebug's single-item form.
    assert.ok(rows[0].liveValue?.includes('"12345"'), `action row: ${rows[0].liveValue}`);
    assert.ok(rows[1].liveValue?.includes('"SMITH"'), `send row: ${rows[1].liveValue}`);
    // Cross-check the label form: two items on ONE line render `label = value` pairs.
    const twoOnALine = traceRowValues(
      [inv({ events: [{ line: 3, event: "line", assigned: { mrn: "12345" }, writes: [{ path: "PID-5.1", value: "SMITH" }] }] })],
      true,
    );
    assert.ok(twoOnALine[0].after.includes('mrn = "12345"'), twoOnALine[0].after);
    assert.ok(twoOnALine[0].after.includes('msg["PID-5.1"] = "SMITH"'), twoOnALine[0].after);
  });

  test("no sample / empty trace ⇒ no values attached (graceful — the toolbar placeholder stands)", () => {
    const none = traceRowValues([], false);
    assert.deepStrictEqual(none, []);
    const rows = twoRows();
    mergeLiveValues(rows, none);
    assert.strictEqual(rows[0].liveValue, undefined);
    assert.strictEqual(rows[1].liveValue, undefined);
  });

  test("a value the CLI already redacted stays a placeholder even under reveal (defense in depth)", () => {
    const gated = traceRowValues(
      [inv({ events: [{ line: 3, event: "line", assigned: { x: "REDACTED" } }] })],
      true,
    );
    assert.ok(gated[0].after.includes("⋯"), gated[0].after);
    assert.ok(!gated[0].after.includes("REDACTED"), gated[0].after);
  });

  test("a live_lookup_skipped annotation renders a warning and suppresses any value on that line", () => {
    const both = traceRowValues(
      [
        inv({
          events: [{ line: 4, event: "line", assigned: { y: "1" } }],
          annotations: [{ line: 4, kind: "live_lookup_skipped", call: "db_lookup" }],
        }),
      ],
      true,
    );
    // source line 4 → 0-based 3: a warning, and NO value decoration there.
    assert.strictEqual(both.filter((iv) => iv.kind === "value" && iv.line === 3).length, 0);
    const warn = both.find((iv) => iv.kind === "warning" && iv.line === 3);
    assert.ok(warn, "expected a live-lookup warning on the annotated line");
    assert.ok(warn?.after.includes("live lookup"), warn?.after);
  });

  test("across traced messages, the newest invocation's value wins for a shared line", () => {
    const first = inv({ events: [{ line: 3, event: "line", assigned: { x: "AAA" } }] });
    const second = inv({ events: [{ line: 3, event: "line", assigned: { x: "BBB" } }] });
    const merged = traceRowValues([first, second], true);
    assert.strictEqual(merged.length, 1);
    assert.ok(merged[0].after.includes('"BBB"'), merged[0].after);
    assert.ok(!merged[0].after.includes('"AAA"'), merged[0].after);
  });
});

// ---- BACKLOG #225 fix: skip disk-sourced live values while the buffer is DIRTY --------------------
// The live-value trace reads the module FROM DISK, but the rows are projected from the LIVE buffer. After
// an unsaved structural edit (insert/delete/move) the buffer's rows shift relative to disk, so the disk
// trace's line numbers describe rows that no longer sit at those coordinates. `shouldAttachLiveValues`
// gates the provider so those stale disk line numbers are NOT mapped onto the shifted rows (which would
// land a marker on the WRONG row); values re-attach on the next save, when disk == buffer.

suite("stepsModel — live values are skipped while the buffer is dirty (BACKLOG #225 misplacement guard)", () => {
  // Reproduces the finding: DISK has a Send on source line 5, so its trace yields a value at 0-based line
  // 4. After inserting one step at the top of the body the BUFFER shifts everything +1 — a Convert Case
  // now occupies line 5 and the Send moved to line 6. The rows below describe that shifted buffer.
  function shiftedBufferRows(): RowViewModel[] {
    return [
      { index: 0, kind: "action", nesting: 0, lineStart: 5, lineEnd: 5, title: "Convert Case", params: [] },
      { index: 1, kind: "send", nesting: 0, lineStart: 6, lineEnd: 6, title: "Send", params: [] },
    ];
  }
  // The disk-sourced trace value on source line 5 (0-based 4) — the Send's value on the PRE-edit file.
  const diskTrace: LiveInlineValue[] = [{ line: 4, after: REDACTED_LIVE_VALUE, kind: "value" }];

  test("dirty ⇒ the disk trace is not attached, so no marker lands on the shifted rows", () => {
    assert.strictEqual(shouldAttachLiveValues(true), false, "dirty buffer ⇒ skip disk-sourced values");
    const rows = shiftedBufferRows();
    // The provider merges `shouldAttachLiveValues(isDirty) ? trace : []` — model that gate here.
    mergeLiveValues(rows, shouldAttachLiveValues(true) ? diskTrace : []);
    assert.strictEqual(rows[0].liveValue, undefined, "no stale marker on the shifted Convert Case row");
    assert.strictEqual(rows[1].liveValue, undefined, "the Send row carries no marker either while dirty");
  });

  test("the pre-fix behavior (attaching the disk trace regardless) DID misplace the marker onto the wrong row", () => {
    // Guards against a regression to the stub/unconditional-merge behavior: mapping the disk trace onto
    // the shifted buffer lands the Send's value on whatever row now occupies stale line 5 — the wrong one.
    const rows = shiftedBufferRows();
    mergeLiveValues(rows, diskTrace);
    assert.strictEqual(rows[0].liveValue, REDACTED_LIVE_VALUE, "unconditional merge misplaces onto Convert Case");
    assert.strictEqual(rows[1].liveValue, undefined, "the real Send row (line 6) is left blank — the defect");
  });

  test("clean (disk == buffer) ⇒ live values attach as usual", () => {
    assert.strictEqual(shouldAttachLiveValues(false), true, "a saved buffer attaches the trace normally");
    // When not dirty the disk trace aligns: a value on 0-based line 4 lands on a row at source line 5.
    const alignedRows: RowViewModel[] = [
      { index: 0, kind: "send", nesting: 0, lineStart: 5, lineEnd: 5, title: "Send", params: [] },
    ];
    mergeLiveValues(alignedRows, shouldAttachLiveValues(false) ? diskTrace : []);
    assert.strictEqual(alignedRows[0].liveValue, REDACTED_LIVE_VALUE, "clean buffer attaches the value");
  });
});
