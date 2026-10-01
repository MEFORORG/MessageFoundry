// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
import * as assert from "assert";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import {
  LiveDebugController,
  buildLiveLenses,
  buildTraceArgs,
  inlineValuesFor,
  invocationsForFile,
  namedElements,
  rowsFromTrace,
  summarize,
  type LiveDryRunRow,
  type LiveTraceEntry,
  type TraceInvocation,
  type TraceRunner,
} from "../../liveDebug";

// A config module shaped exactly like samples/config/IB_ACME_ADT.py: one inbound, one @router, one
// @handler — so the element line-scan + name extraction is exercised against realistic source.
const CONFIG_TEXT = [
  "from messagefoundry import MLLP, Send, handler, inbound, outbound, router", // 0
  "", // 1
  'inbound("IB_ACME_ADT", MLLP(port=2600), router="acme_adt_router")', // 2 — inbound
  'outbound("OB_ACME_ADT", MLLP(host="h", port=1))', // 3 — outbound
  "", // 4
  '@router("acme_adt_router")', // 5 — router
  "def route(msg):", // 6
  '    return ["acme_adt_handler"]', // 7
  "", // 8
  '@handler("acme_adt_handler")', // 9 — handler
  "def handle(msg):", // 10
  '    return Send("OB_ACME_ADT", msg)', // 11
].join("\n");

function row(over: Partial<LiveDryRunRow>): LiveDryRunRow {
  return {
    inbound: "IB_ACME_ADT",
    disposition: "RECEIVED",
    handlers: ["acme_adt_handler"],
    deliveries: [{ to: "OB_ACME_ADT" }],
    error: null,
    ...over,
  };
}

// A canned traced-dryrun entry (one message). `invocations` default empty — the v1 CodeLens summary
// reads only the top-level fields, so most summary tests leave them out.
function traceEntry(over: Partial<LiveTraceEntry>): LiveTraceEntry {
  return {
    inbound: "IB_ACME_ADT",
    disposition: "RECEIVED",
    handlers: ["acme_adt_handler"],
    sends: [{ outbound: "OB_ACME_ADT" }],
    error: null,
    trace_ok: true,
    invocations: [],
    ...over,
  };
}

function inv(over: Partial<TraceInvocation>): TraceInvocation {
  return {
    kind: "handler",
    name: "acme_adt_handler",
    module: "IB_ACME_ADT",
    file: "/cfg/IB_ACME_ADT.py",
    def_line: 10,
    events: [],
    disposition: "RECEIVED",
    sends: [{ outbound: "OB_ACME_ADT" }],
    routed_to: [],
    annotations: [],
    ...over,
  };
}

suite("liveDebug summarize", () => {
  test("single message, single handler → sole handler + attributable send count", () => {
    const s = summarize([row({})]);
    assert.strictEqual(s.messageCount, 1);
    assert.deepStrictEqual(s.handlersUnion, ["acme_adt_handler"]);
    assert.strictEqual(s.soleHandler, "acme_adt_handler");
    assert.strictEqual(s.totalSends, 1);
    assert.deepStrictEqual(s.dispositions, [["RECEIVED", 1]]);
    assert.deepStrictEqual(s.errors, []);
  });

  test("two distinct handlers in one message → NOT unambiguous (soleHandler null)", () => {
    const s = summarize([
      row({ handlers: ["h1", "h2"], deliveries: [{ to: "A" }, { to: "B" }] }),
    ]);
    assert.deepStrictEqual(s.handlersUnion, ["h1", "h2"]);
    assert.strictEqual(s.soleHandler, null); // flattened attribution — can't split the 2 sends
    assert.strictEqual(s.totalSends, 2);
  });

  test("two messages picking DIFFERENT single handlers → ambiguous across the run", () => {
    const s = summarize([row({ handlers: ["h1"] }), row({ handlers: ["h2"] })]);
    assert.deepStrictEqual(s.handlersUnion, ["h1", "h2"]);
    assert.strictEqual(s.soleHandler, null);
    assert.strictEqual(s.messageCount, 2);
  });

  test("unrouted message → no handlers, no sole handler, UNROUTED disposition", () => {
    const s = summarize([row({ handlers: [], deliveries: [], disposition: "UNROUTED" })]);
    assert.deepStrictEqual(s.handlersUnion, []);
    assert.strictEqual(s.soleHandler, null);
    assert.strictEqual(s.totalSends, 0);
    assert.deepStrictEqual(s.dispositions, [["UNROUTED", 1]]);
  });

  test("same sole handler across many messages stays unambiguous; sends sum", () => {
    const s = summarize([row({}), row({ deliveries: [{ to: "A" }, { to: "B" }] })]);
    assert.strictEqual(s.soleHandler, "acme_adt_handler");
    assert.strictEqual(s.totalSends, 3);
    assert.deepStrictEqual(s.dispositions, [["RECEIVED", 2]]);
  });

  test("error rows are collected distinctly", () => {
    const s = summarize([
      row({ disposition: "ERROR", handlers: [], deliveries: [], error: "boom" }),
      row({ disposition: "ERROR", handlers: [], deliveries: [], error: "boom" }),
    ]);
    assert.deepStrictEqual(s.errors, ["boom"]);
    assert.deepStrictEqual(s.dispositions, [["ERROR", 2]]);
  });
});

suite("liveDebug rowsFromTrace", () => {
  test("projects the v1 CodeLens fields (sends → deliveries) off a trace entry", () => {
    const rows = rowsFromTrace([
      traceEntry({ handlers: ["h1"], sends: [{ outbound: "OB_A" }, { outbound: "OB_B" }] }),
    ]);
    assert.deepStrictEqual(rows, [
      {
        inbound: "IB_ACME_ADT",
        disposition: "RECEIVED",
        handlers: ["h1"],
        deliveries: [{ to: "OB_A" }, { to: "OB_B" }],
        error: null,
      },
    ]);
  });
});

suite("liveDebug namedElements", () => {
  test("locates inbound/router/handler with their argument names", () => {
    const els = namedElements(CONFIG_TEXT);
    assert.deepStrictEqual(
      els,
      [
        { line: 2, kind: "inbound", name: "IB_ACME_ADT" },
        { line: 3, kind: "outbound", name: "OB_ACME_ADT" },
        { line: 5, kind: "router", name: "acme_adt_router" },
        { line: 9, kind: "handler", name: "acme_adt_handler" },
      ],
    );
  });
});

suite("liveDebug buildLiveLenses", () => {
  test("router routing lens + inbound disposition lens + sole-handler send count", () => {
    const lenses = buildLiveLenses(namedElements(CONFIG_TEXT), summarize([row({})]), "adt_a01.hl7", false);
    const byLine = new Map(lenses.map((l) => [l.line, l.title]));
    assert.ok(byLine.get(2)?.includes("adt_a01.hl7: RECEIVED"), `inbound lens: ${byLine.get(2)}`);
    assert.ok(byLine.get(5)?.includes("routed → [acme_adt_handler]"), `router lens: ${byLine.get(5)}`);
    assert.ok(byLine.get(9)?.includes("1 Send"), `handler lens: ${byLine.get(9)}`);
    assert.ok(!byLine.has(3), "no lens on the outbound line");
  });

  test("multi-handler run: router lists both, but NO per-handler send count is attributed", () => {
    const summary = summarize([
      row({ handlers: ["acme_adt_handler", "other_handler"], deliveries: [{ to: "A" }, { to: "B" }] }),
    ]);
    const lenses = buildLiveLenses(namedElements(CONFIG_TEXT), summary, "adt.hl7", false);
    const byLine = new Map(lenses.map((l) => [l.line, l.title]));
    assert.ok(byLine.get(5)?.includes("routed → [acme_adt_handler, other_handler]"));
    assert.ok(!byLine.has(9), "no send-count lens when >1 handler ran (ambiguous attribution)");
  });

  test("unrouted run renders 'routed → (nowhere)'", () => {
    const summary = summarize([row({ handlers: [], deliveries: [], disposition: "UNROUTED" })]);
    const lenses = buildLiveLenses(namedElements(CONFIG_TEXT), summary, "x.hl7", false);
    const byLine = new Map(lenses.map((l) => [l.line, l.title]));
    assert.ok(byLine.get(5)?.includes("routed → (nowhere)"));
  });
});

// ---- v2: inline decorations + PHI gating --------------------------------------------------------

suite("liveDebug buildTraceArgs (--show-phi gating)", () => {
  test("omits --show-phi by default (reveal off)", () => {
    const args = buildTraceArgs("samples/config", "/synthetic/adt.hl7", false);
    assert.deepStrictEqual(args, [
      "dryrun",
      "--config",
      "samples/config",
      "--messages",
      "/synthetic/adt.hl7",
      "--trace",
      "json",
    ]);
    assert.ok(!args.includes("--show-phi"), "reveal-off argv must NOT contain --show-phi");
  });

  test("appends --show-phi only when showPhi is set (reveal on)", () => {
    const args = buildTraceArgs("samples/config", "/synthetic/adt.hl7", true);
    assert.ok(args.includes("--show-phi"), "reveal-on argv must request real values");
    assert.ok(args.includes("--trace") && args[args.indexOf("--trace") + 1] === "json");
  });
});

suite("liveDebug inlineValuesFor (PHI-safe inline values)", () => {
  const producing = inv({
    events: [
      { line: 11, event: "line", assigned: { mrn: "12345" } }, // 1-based → 0-based 10
      { line: 12, event: "line", writes: [{ path: "PID-5.1", value: "SMITH" }] }, // → 0-based 11
    ],
  });

  test("values are REDACTED by default (reveal off) — no real value in after-text or hover", () => {
    const off = inlineValuesFor([producing], false);
    assert.strictEqual(off.length, 2);
    for (const iv of off) {
      assert.strictEqual(iv.kind, "value");
      assert.ok(iv.after.includes("⋯"), `expected placeholder, got: ${iv.after}`);
      assert.ok(!iv.after.includes("12345") && !iv.after.includes("SMITH"), iv.after);
      assert.ok(!iv.hover.includes("12345") && !iv.hover.includes("SMITH"), iv.hover);
    }
  });

  test("real values appear ONLY when reveal is set, mapped to their producing line", () => {
    const on = inlineValuesFor([producing], true);
    const byLine = new Map(on.map((iv) => [iv.line, iv]));
    // event.line 11 → 0-based 10 shows the local; event.line 12 → 0-based 11 shows the write.
    assert.strictEqual(byLine.get(10)?.line, 10);
    assert.ok(byLine.get(10)?.after.includes('"12345"'), byLine.get(10)?.after);
    assert.ok(byLine.get(11)?.after.includes('"SMITH"'), byLine.get(11)?.after);
    assert.ok(byLine.get(11)?.hover.includes("SMITH"), byLine.get(11)?.hover);
  });

  test("a value the CLI still redacted stays a placeholder even under reveal", () => {
    const gated = inlineValuesFor(
      [inv({ events: [{ line: 11, event: "line", assigned: { x: "REDACTED" } }] })],
      true,
    );
    assert.ok(gated[0].after.includes("⋯"), gated[0].after);
    assert.ok(!gated[0].after.includes("REDACTED"), gated[0].after);
  });

  test("live_lookup_skipped renders a warning on its line (independent of reveal)", () => {
    const warnInv = inv({
      events: [{ line: 11, event: "line", assigned: { x: "REDACTED" } }],
      annotations: [{ line: 13, kind: "live_lookup_skipped", call: "db_lookup" }],
    });
    const res = inlineValuesFor([warnInv], false);
    const warn = res.find((iv) => iv.kind === "warning");
    assert.ok(warn, "expected a warning decoration");
    assert.strictEqual(warn?.line, 12, "annotation line 13 (1-based) → 12 (0-based)");
    assert.ok(warn?.after.includes("live lookup"), warn?.after);
    assert.ok(warn?.hover.includes("db_lookup"), warn?.hover);
  });

  test("a warning suppresses a value decoration on the same line", () => {
    const both = inv({
      events: [{ line: 12, event: "line", assigned: { y: "1" } }],
      annotations: [{ line: 12, kind: "live_lookup_skipped", call: "fhir_lookup" }],
    });
    const r = inlineValuesFor([both], true);
    assert.strictEqual(r.filter((iv) => iv.kind === "value" && iv.line === 11).length, 0);
    assert.strictEqual(r.filter((iv) => iv.kind === "warning" && iv.line === 11).length, 1);
  });

  test("across messages, the newest invocation's value wins for a shared line", () => {
    const first = inv({ events: [{ line: 11, event: "line", assigned: { x: "AAA" } }] });
    const second = inv({ events: [{ line: 11, event: "line", assigned: { x: "BBB" } }] });
    const merged = inlineValuesFor([first, second], true);
    assert.strictEqual(merged.length, 1);
    assert.ok(merged[0].after.includes('"BBB"'), merged[0].after);
    assert.ok(!merged[0].after.includes('"AAA"'), merged[0].after);
  });
});

suite("liveDebug invocationsForFile", () => {
  test("filters to the active module by resolved path", () => {
    const entries = [
      traceEntry({ invocations: [inv({ file: "/cfg/A.py" }), inv({ file: "/cfg/B.py" })] }),
    ];
    const only = invocationsForFile(entries, "/cfg/A.py");
    assert.strictEqual(only.length, 1);
    assert.strictEqual(only[0].file, "/cfg/A.py");
  });
});

suite("LiveDebugController with a mocked traced-dryrun spawn", () => {
  // The spawn seam is injected: a canned runner stands in for `messagefoundry dryrun --trace json`, so
  // the whole pipeline (run → store rows/trace → CodeLens summaries) runs with NO Python engine.
  test("canned trace JSON flows through to CodeLens summaries (no --show-phi by default)", async () => {
    let calledWith: { sample: string; cwd: string; showPhi: boolean } | undefined;
    const runner: TraceRunner = async (sample, cwd, showPhi) => {
      calledWith = { sample, cwd, showPhi };
      return [traceEntry({})];
    };
    const controller = new LiveDebugController(runner);
    try {
      await controller.runWith("/synthetic/adt_a01.hl7", "/workspace");
      assert.deepStrictEqual(calledWith, {
        sample: "/synthetic/adt_a01.hl7",
        cwd: "/workspace",
        showPhi: false, // MEFOR Live alone NEVER requests PHI
      });

      const lenses = controller.lensesForText(CONFIG_TEXT);
      const byLine = new Map(lenses.map((l) => [l.line, l.title]));
      assert.ok(byLine.get(2)?.includes("adt_a01.hl7: RECEIVED"), `inbound: ${byLine.get(2)}`);
      assert.ok(byLine.get(5)?.includes("routed → [acme_adt_handler]"), `router: ${byLine.get(5)}`);
      assert.ok(byLine.get(9)?.includes("1 Send"), `handler: ${byLine.get(9)}`);
    } finally {
      controller.dispose();
    }
  });

  test("a runner rejection surfaces as an error lens (no live engine, no crash)", async () => {
    const runner: TraceRunner = () =>
      Promise.reject(new Error("config has multiple inbound connections"));
    const controller = new LiveDebugController(runner);
    try {
      await controller.runWith("/synthetic/x.hl7", "/workspace");
      const lenses = controller.lensesForText(CONFIG_TEXT);
      assert.strictEqual(lenses.length, 1);
      assert.ok(lenses[0].title.includes("multiple inbound connections"), lenses[0].title);
    } finally {
      controller.dispose();
    }
  });

  test("a superseded run's late result is discarded (newest run wins)", async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const slow = [traceEntry({ handlers: ["stale_handler"] })];
    const fresh = [traceEntry({ handlers: ["fresh_handler"] })];
    let call = 0;
    const runner: TraceRunner = async () => {
      call += 1;
      if (call === 1) {
        await gate;
        return slow;
      }
      return fresh;
    };
    const controller = new LiveDebugController(runner);
    try {
      const first = controller.runWith("/a.hl7", "/ws"); // starts, awaits the gate
      await controller.runWith("/b.hl7", "/ws"); // supersedes with fresh rows
      release(); // let the stale run finish AFTER the fresh one already stored its rows
      await first;

      const lenses = controller.lensesForText(CONFIG_TEXT);
      const routerLens = lenses.find((l) => l.line === 5)?.title ?? "";
      assert.ok(routerLens.includes("fresh_handler"), `newest run should win: ${routerLens}`);
      assert.ok(!routerLens.includes("stale_handler"), "stale run's late result must be dropped");
    } finally {
      controller.dispose();
    }
  });
});

suite("LiveDebugController per-run reveal (ASVS 14.2.6, vault BACKLOG #1187)", () => {
  // A reveal is the user's act on ONE run, never a session state (owner rulings R13 and R15 of
  // ASVS-OWNER-RULINGS-2026-09-28-BATCH174.md). These pin the three arms: masked by default, shown
  // for the run that asked, and masked again on the very next run.
  test("a run with no reveal request is masked (control)", async () => {
    const calls: boolean[] = [];
    const runner: TraceRunner = async (_s, _c, showPhi) => {
      calls.push(showPhi);
      return [traceEntry({})];
    };
    const controller = new LiveDebugController(runner);
    try {
      await controller.runWith("/synthetic/adt.hl7", "/ws");
      assert.deepStrictEqual(calls, [false], "a default run must NOT pass --show-phi");
      assert.strictEqual(controller.isShowingValues(), false);
    } finally {
      controller.dispose();
    }
  });

  test("the run that asks shows values, and the next run is masked again", async () => {
    const calls: boolean[] = [];
    const runner: TraceRunner = async (_s, _c, showPhi) => {
      calls.push(showPhi);
      return [traceEntry({})];
    };
    const controller = new LiveDebugController(runner);
    try {
      await controller.runWith("/synthetic/adt.hl7", "/ws", true);
      assert.deepStrictEqual(calls, [true], "the revealed run passes --show-phi");
      assert.strictEqual(controller.isShowingValues(), true);

      // The next run (a save does exactly this) carries no reveal request and stores a masked result.
      await controller.runWith("/synthetic/adt.hl7", "/ws");
      assert.deepStrictEqual(calls, [true, false], "the run after a reveal must NOT pass --show-phi");
      assert.strictEqual(controller.isShowingValues(), false, "the reveal must not outlive its run");
    } finally {
      controller.dispose();
    }
  });

  test("a revealed run that fails can still be hidden, error text and all", async () => {
    // The --show-phi CLI's error text is unredacted, so a failed reveal counts as shown.
    const runner: TraceRunner = () => Promise.reject(new Error("boom"));
    const controller = new LiveDebugController(runner);
    try {
      await controller.runWith("/synthetic/adt.hl7", "/ws", true);
      assert.strictEqual(controller.isShowingValues(), true);
      assert.strictEqual(controller["entries"], null, "a failed run stores no trace");
      await controller.hideValues();
      assert.strictEqual(controller.isShowingValues(), false);
      assert.strictEqual(controller["error"], null, "the revealed run's error text must go");
    } finally {
      controller.dispose();
    }
  });

  test("a revealed run ends when the next run STARTS, not when it lands", async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const runner: TraceRunner = async (_s, _c, showPhi) => {
      if (!showPhi) {
        await gate; // a slow masked run: the revealed values must not stay painted meanwhile
      }
      return [traceEntry({})];
    };
    const controller = new LiveDebugController(runner);
    try {
      await controller.runWith("/a.hl7", "/ws", true);
      assert.strictEqual(controller.isShowingValues(), true);
      const masked = controller.runWith("/a.hl7", "/ws");
      assert.strictEqual(controller.isShowingValues(), false);
      assert.strictEqual(controller["entries"], null, "the revealed trace must go as the run starts");
      release();
      await masked;
      assert.strictEqual(controller.isShowingValues(), false);
    } finally {
      controller.dispose();
    }
  });

  test("a revealed run superseded by a masked one leaves the newest run masked", async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const runner: TraceRunner = async (_s, _c, showPhi) => {
      if (showPhi) {
        await gate; // the reveal is slow, so a save-triggered masked run overtakes it
      }
      return [traceEntry({})];
    };
    const controller = new LiveDebugController(runner);
    try {
      const reveal = controller.runWith("/a.hl7", "/ws", true);
      await controller.runWith("/a.hl7", "/ws");
      release();
      await reveal;
      assert.strictEqual(controller.isShowingValues(), false, "a superseded reveal must not land");
    } finally {
      controller.dispose();
    }
  });

  test("a masked run's lens tooltip shows an error count, never the error text (ground d1)", async () => {
    // The CLI's masked error is scrubbed, not removed: a lone identifier passes it whole.
    const quoted = "unmapped patient 900123456";
    const runner: TraceRunner = async () => [traceEntry({ disposition: "ERROR", error: quoted })];
    const controller = new LiveDebugController(runner);
    try {
      await controller.runWith("/synthetic/adt.hl7", "/ws");
      const masked = controller.lensesForText(CONFIG_TEXT).find((l) => l.line === 2);
      assert.ok(masked?.tooltip?.startsWith("1 of 1 message(s) failed."), masked?.tooltip);
      assert.ok(!masked?.tooltip?.includes(quoted), `masked tooltip quoted the error: ${masked?.tooltip}`);

      await controller.runWith("/synthetic/adt.hl7", "/ws", true); // control: the revealed run
      const shown = controller.lensesForText(CONFIG_TEXT).find((l) => l.line === 2);
      assert.strictEqual(shown?.tooltip, `Errors: ${quoted}`);
    } finally {
      controller.dispose();
    }
  });

  test("hideValues drops a shown run's values before the next run", async () => {
    const controller = new LiveDebugController(async () => [traceEntry({})]);
    try {
      await controller.runWith("/synthetic/adt.hl7", "/ws", true);
      assert.strictEqual(controller.isShowingValues(), true);
      await controller.hideValues(); // Live is off here, so this only hides; no run follows
      assert.strictEqual(controller.isShowingValues(), false);
      assert.strictEqual(controller["entries"], null, "the revealed trace must not stay in memory");
      assert.strictEqual(controller["rows"], null, "a revealed run's error text must not stay either");
    } finally {
      controller.dispose();
    }
  });
});

suite("LiveDebugController trigger paths choose --show-phi (vault BACKLOG #1187)", () => {
  // These drive the real triggers rather than runWith, so a trigger that re-arms a reveal fails here.
  // The integration host opens no folder, so the controller gets a fixed workspace path, and a real
  // synthetic sample file so no quick pick opens.
  const tempDirs: string[] = [];
  suiteTeardown(() => {
    for (const dir of tempDirs) {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  function syntheticSample(): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mf-live-"));
    tempDirs.push(dir);
    const file = path.join(dir, "adt.hl7");
    fs.writeFileSync(file, "MSH|^~\\&|SYN|SYN|||20260101000000||ADT^A01|1|P|2.5\r");
    return file;
  }

  async function waitFor(cond: () => boolean, ms: number): Promise<void> {
    const end = Date.now() + ms;
    while (!cond() && Date.now() < end) {
      await new Promise((r) => setTimeout(r, 25));
    }
  }

  test("revealOnce reveals one run; Live off then on, and a save, are masked", async () => {
    const calls: boolean[] = [];
    const runner: TraceRunner = async (_s, _c, showPhi) => {
      calls.push(showPhi);
      return [traceEntry({})];
    };
    const controller = new LiveDebugController(runner, () => "/ws");
    try {
      await controller.runWith(syntheticSample(), "/ws"); // choose the sample, masked
      await controller.revealOnce(); // Live is off: this turns it on and reveals that one run
      assert.strictEqual(controller.isEnabled(), true);
      assert.deepStrictEqual(calls, [false, true]);
      assert.strictEqual(controller.isShowingValues(), true);

      controller["scheduleRun"](); // exactly what a save of a config module does
      await waitFor(() => calls.length === 3, 5000);
      assert.deepStrictEqual(calls, [false, true, false], "a save after a reveal must be masked");
      assert.strictEqual(controller.isShowingValues(), false);

      await controller.revealOnce();
      await controller.toggle(); // Live off clears the shown run
      assert.strictEqual(controller.isShowingValues(), false);
      assert.strictEqual(controller["entries"], null);
      await controller.toggle(); // Live on again runs masked
      assert.deepStrictEqual(calls, [false, true, false, true, false]);
      assert.strictEqual(controller.isShowingValues(), false);
    } finally {
      controller.dispose();
    }
  });

  test("hideValues cancels a reveal still running", async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const calls: boolean[] = [];
    const runner: TraceRunner = async (_s, _c, showPhi) => {
      calls.push(showPhi);
      if (showPhi) {
        await gate;
      }
      return [traceEntry({})];
    };
    const controller = new LiveDebugController(runner, () => "/ws");
    try {
      await controller.runWith(syntheticSample(), "/ws");
      await controller.toggle(); // Live on, masked
      const reveal = controller.revealOnce(); // starts a --show-phi run that has not landed
      await controller.hideValues();
      release();
      await reveal;
      assert.deepStrictEqual(calls, [false, false, true, false]);
      assert.strictEqual(controller.isShowingValues(), false, "a cancelled reveal must not land");
    } finally {
      controller.dispose();
    }
  });

  test("turning Live off orphans a reveal still running", async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const runner: TraceRunner = async (_s, _c, showPhi) => {
      if (showPhi) {
        await gate;
      }
      return [traceEntry({})];
    };
    const controller = new LiveDebugController(runner, () => "/ws");
    try {
      await controller.runWith(syntheticSample(), "/ws");
      await controller.toggle(); // Live on, masked
      const reveal = controller.revealOnce();
      await controller.toggle(); // Live off; no masked re-run follows to supersede the reveal
      release();
      await reveal;
      assert.strictEqual(controller.isShowingValues(), false, "a reveal landing after Live off must store nothing");
      assert.strictEqual(controller["entries"], null);
    } finally {
      controller.dispose();
    }
  });
});

interface Pkg {
  contributes: {
    commands: Array<{ command: string }>;
    configuration: { properties: Record<string, { type?: string; default?: unknown }> };
  };
}

function pkg(): Pkg {
  return JSON.parse(
    fs.readFileSync(path.join(__dirname, "..", "..", "..", "package.json"), "utf8"),
  ) as Pkg;
}

suite("liveDebug contributions", () => {
  test("package.json contributes the Live toggle command", () => {
    const cmds = pkg().contributes.commands.map((c) => c.command);
    assert.ok(cmds.includes("messagefoundry.toggleLiveDebug"), "toggleLiveDebug command missing");
  });

  test("package.json contributes the per-run reveal and hide commands, and no session toggle", () => {
    const cmds = pkg().contributes.commands.map((c) => c.command);
    assert.ok(cmds.includes("messagefoundry.revealValuesOnce"), "revealValuesOnce command missing");
    assert.ok(cmds.includes("messagefoundry.hideValues"), "hideValues command missing");
    assert.ok(
      !cmds.includes("messagefoundry.toggleRevealValues"),
      "the session-wide reveal toggle must stay retired (vault BACKLOG #1187)",
    );
  });

  test("package.json contributes the debounce config prop", () => {
    const prop = pkg().contributes.configuration.properties["messagefoundry.liveDebug.debounceMs"];
    assert.ok(prop, "liveDebug.debounceMs config prop missing");
    assert.strictEqual(prop.type, "integer");
    assert.strictEqual(prop.default, 400);
  });
});
