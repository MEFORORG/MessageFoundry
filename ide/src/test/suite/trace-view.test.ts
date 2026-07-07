import * as assert from "assert";

import {
  buildCoverage,
  buildProfile,
  buildTraceDetail,
  functionSpan,
  type TraceEntry,
  type TraceEvent,
  type TraceInvocation,
} from "../../traceView";

// A canned config module. Line numbers (1-based) referenced by the fixtures below:
//   4  @router("r")            8  <blank>            12 def handle(msg):
//   5  def route(msg):         9  <blank>            13     # transform each MSH-3
//   6      if ... == "ADT":   10  <blank>            14     for seg in range(3):
//   7          return ["h"]   11  @handler("h")      15         msg["MSH-3"] = "X"
//   8      return []                                 16     return Send("out", msg)
const SOURCE = [
  "from messagefoundry import Send, handler, router", // 1
  "", // 2
  "", // 3
  '@router("r")', // 4
  "def route(msg):", // 5
  '    if msg["MSH-9.1"] == "ADT":', // 6
  '        return ["h"]', // 7
  "    return []", // 8
  "", // 9
  "", // 10
  '@handler("h")', // 11
  "def handle(msg):", // 12
  "    # transform each MSH-3", // 13
  "    for seg in range(3):", // 14
  '        msg["MSH-3"] = "X"', // 15
  '    return Send("out", msg)', // 16
].join("\n");

function ev(line: number, t?: number): TraceEvent {
  const e: TraceEvent = { line, event: "line", assigned: {} };
  if (t !== undefined) {
    e.t = t;
  }
  return e;
}

// Router that took the ADT branch: lines 6 and 7 ran; line 8 (return []) did NOT.
const ROUTER: TraceInvocation = {
  kind: "router",
  name: "r",
  module: "IB_X",
  file: "C:/cfg/IB_X.py",
  def_line: 4,
  events: [ev(6, 1e-6), ev(7, 2e-6)],
  disposition: "received",
  sends: [],
  routed_to: ["h"],
  annotations: [],
};

// Handler with a 3-iteration loop: line 14 (for) x4, line 15 (body) x3 and HOT, line 16 (return) x1.
const HANDLER: TraceInvocation = {
  kind: "handler",
  name: "h",
  module: "IB_X",
  file: "C:/cfg/IB_X.py",
  def_line: 11,
  events: [
    ev(14, 1e-6),
    ev(15, 1e-5),
    ev(14, 1e-6),
    ev(15, 1e-5),
    ev(14, 1e-6),
    ev(15, 1e-5),
    ev(14, 1e-6),
    ev(16, 2e-6),
  ],
  disposition: "received",
  sends: [{ outbound: "out" }],
  routed_to: [],
  annotations: [],
};

suite("traceView.functionSpan", () => {
  test("resolves the def under a decorator anchor and walks the body by indent", () => {
    const lines = SOURCE.split("\n");
    const span = functionSpan(lines, 4); // def_line points at the @router line (Py3.14)
    // start = the decorator line (idx 3), header = the def line (idx 4), end = last body stmt (idx 7 = line 8)
    assert.strictEqual(span.start, 3);
    assert.strictEqual(span.header, 4);
    assert.strictEqual(span.end, 7);
  });

  test("stops at the next dedented (module-level) construct", () => {
    const lines = SOURCE.split("\n");
    const span = functionSpan(lines, 11); // @handler line
    assert.strictEqual(span.start, 10); // @handler
    assert.strictEqual(span.header, 11); // def handle
    assert.strictEqual(span.end, 15); // return Send(...) — line 16
  });
});

suite("traceView.buildCoverage", () => {
  test("marks executed vs. not-executed executable lines; context is non-executable", () => {
    const cov = buildCoverage(SOURCE, ROUTER);
    assert.strictEqual(cov.sourceAvailable, true);
    // executable code lines are 6, 7, 8; 6 and 7 ran, 8 did not.
    assert.strictEqual(cov.executable, 3);
    assert.strictEqual(cov.executed, 2);
    assert.ok(Math.abs(cov.pct - (2 / 3) * 100) < 1e-9);

    const byLine = new Map(cov.lines.map((l) => [l.line, l]));
    assert.strictEqual(byLine.get(4)?.role, "def"); // @router decorator
    assert.strictEqual(byLine.get(5)?.role, "def"); // def route
    assert.strictEqual(byLine.get(6)?.executed, true);
    assert.strictEqual(byLine.get(7)?.executed, true);
    assert.strictEqual(byLine.get(8)?.executable, true);
    assert.strictEqual(byLine.get(8)?.executed, false); // the un-taken branch
  });

  test("comments/blank lines are shown but do not count toward coverage", () => {
    const cov = buildCoverage(SOURCE, HANDLER);
    const byLine = new Map(cov.lines.map((l) => [l.line, l]));
    assert.strictEqual(byLine.get(13)?.role, "comment");
    assert.strictEqual(byLine.get(13)?.executable, false);
    // executable lines: 14, 15, 16 — all ran (loop).
    assert.strictEqual(cov.executable, 3);
    assert.strictEqual(cov.executed, 3);
    assert.strictEqual(cov.pct, 100);
    // loop body hit multiple times
    assert.strictEqual(byLine.get(15)?.hits, 3);
    assert.strictEqual(byLine.get(14)?.hits, 4);
  });

  test("falls back to executed-line list when the source is unavailable", () => {
    const cov = buildCoverage(null, HANDLER);
    assert.strictEqual(cov.sourceAvailable, false);
    // only the lines that actually fired, sorted, each with its hit count
    assert.deepStrictEqual(
      cov.lines.map((l) => l.line),
      [14, 15, 16],
    );
    assert.strictEqual(cov.executed, cov.executable);
    assert.strictEqual(cov.pct, 100);
    assert.strictEqual(cov.lines.find((l) => l.line === 15)?.hits, 3);
  });

  test("a truncated trace is flagged on the coverage model", () => {
    const cov = buildCoverage(SOURCE, { ...HANDLER, truncated: true });
    assert.strictEqual(cov.truncated, true);
  });
});

suite("traceView.buildProfile", () => {
  test("sums per-line time across hits, ranks hottest first, computes %", () => {
    const prof = buildProfile(SOURCE, HANDLER);
    assert.strictEqual(prof.hasTiming, true);
    // total = 14:(4×1e-6) + 15:(3×1e-5) + 16:(1×2e-6) = 4e-6 + 3e-5 + 2e-6 = 3.6e-5
    assert.ok(Math.abs(prof.totalSeconds - 3.6e-5) < 1e-12);
    // hottest is line 15 (the loop body)
    assert.strictEqual(prof.lines[0].line, 15);
    assert.strictEqual(prof.lines[0].hits, 3);
    assert.ok(Math.abs(prof.lines[0].seconds - 3e-5) < 1e-12);
    assert.ok(Math.abs(prof.lines[0].pct - (3e-5 / 3.6e-5) * 100) < 1e-6);
    // line text is carried through from the source
    assert.strictEqual(prof.lines[0].text.trim(), 'msg["MSH-3"] = "X"');
    // percentages of the timed lines sum to ~100
    const sum = prof.lines.reduce((a, l) => a + l.pct, 0);
    assert.ok(Math.abs(sum - 100) < 1e-6);
  });

  test("reports hasTiming=false for a pre-#84 trace with no `t` fields", () => {
    const noTiming: TraceInvocation = {
      ...HANDLER,
      events: [ev(14), ev(15), ev(16)], // no `t`
    };
    const prof = buildProfile(SOURCE, noTiming);
    assert.strictEqual(prof.hasTiming, false);
    assert.strictEqual(prof.totalSeconds, 0);
    // lines still enumerated (for the hit counts), just with 0 seconds / 0%
    assert.strictEqual(prof.lines.length, 3);
    assert.ok(prof.lines.every((l) => l.seconds === 0 && l.pct === 0));
  });
});

suite("traceView.buildTraceDetail", () => {
  const entry: TraceEntry = {
    source: "adt_a01.hl7",
    disposition: "received",
    trace_ok: true,
    invocations: [ROUTER, HANDLER],
  };

  test("assembles per-invocation coverage + profile and aggregates totals", () => {
    const detail = buildTraceDetail(entry, () => SOURCE);
    assert.strictEqual(detail.source, "adt_a01.hl7");
    assert.strictEqual(detail.traceOk, true);
    assert.strictEqual(detail.hasTiming, true);
    assert.strictEqual(detail.invocations.length, 2);
    assert.strictEqual(detail.invocations[0].kind, "router");
    assert.strictEqual(detail.invocations[1].kind, "handler");
    // total = router (1e-6 + 2e-6 = 3e-6) + handler (3.6e-5) = 3.9e-5
    assert.ok(Math.abs(detail.totalSeconds - 3.9e-5) < 1e-12);
    assert.strictEqual(detail.invocations[1].coverage.executed, 3);
  });

  test("readSource returning null degrades that invocation gracefully", () => {
    const detail = buildTraceDetail(entry, () => null);
    // both invocations fall back to executed-line-only coverage
    assert.ok(detail.invocations.every((v) => v.coverage.sourceAvailable === false));
    // timing still aggregates (it comes from events, not the source)
    assert.strictEqual(detail.hasTiming, true);
  });
});
