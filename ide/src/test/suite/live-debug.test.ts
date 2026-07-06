import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

import {
  LiveDebugController,
  buildLiveLenses,
  namedElements,
  summarize,
  type DryRunner,
  type LiveDryRunRow,
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
    const lenses = buildLiveLenses(namedElements(CONFIG_TEXT), summarize([row({})]), "adt_a01.hl7");
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
    const lenses = buildLiveLenses(namedElements(CONFIG_TEXT), summary, "adt.hl7");
    const byLine = new Map(lenses.map((l) => [l.line, l.title]));
    assert.ok(byLine.get(5)?.includes("routed → [acme_adt_handler, other_handler]"));
    assert.ok(!byLine.has(9), "no send-count lens when >1 handler ran (ambiguous attribution)");
  });

  test("unrouted run renders 'routed → (nowhere)'", () => {
    const summary = summarize([row({ handlers: [], deliveries: [], disposition: "UNROUTED" })]);
    const lenses = buildLiveLenses(namedElements(CONFIG_TEXT), summary, "x.hl7");
    const byLine = new Map(lenses.map((l) => [l.line, l.title]));
    assert.ok(byLine.get(5)?.includes("routed → (nowhere)"));
  });
});

suite("LiveDebugController with a mocked dryrun spawn", () => {
  // The spawn seam is injected: a canned runner stands in for `messagefoundry dryrun --json`, so the
  // whole pipeline (run → store rows → CodeLens summaries) runs with NO Python engine and no network.
  test("canned dryrun JSON flows through to CodeLens summaries", async () => {
    const canned: LiveDryRunRow[] = [row({})];
    let calledWith: { sample: string; cwd: string } | undefined;
    const runner: DryRunner = async (sample, cwd) => {
      calledWith = { sample, cwd };
      return canned;
    };
    const controller = new LiveDebugController(runner);
    try {
      await controller.runWith("/synthetic/adt_a01.hl7", "/workspace");
      assert.deepStrictEqual(calledWith, { sample: "/synthetic/adt_a01.hl7", cwd: "/workspace" });

      const lenses = controller.lensesForText(CONFIG_TEXT);
      const byLine = new Map(lenses.map((l) => [l.line, l.title]));
      // The label is derived from the sample basename, and the routing/disposition/send lenses reflect
      // the canned row — proving the mocked spawn's JSON reached the rendered lenses.
      assert.ok(byLine.get(2)?.includes("adt_a01.hl7: RECEIVED"), `inbound: ${byLine.get(2)}`);
      assert.ok(byLine.get(5)?.includes("routed → [acme_adt_handler]"), `router: ${byLine.get(5)}`);
      assert.ok(byLine.get(9)?.includes("1 Send"), `handler: ${byLine.get(9)}`);
    } finally {
      controller.dispose();
    }
  });

  test("a runner rejection surfaces as an error lens (no live engine, no crash)", async () => {
    const runner: DryRunner = () => Promise.reject(new Error("config has multiple inbound connections"));
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
    // First run blocks on the gate; second run resolves immediately with different rows.
    const slow: LiveDryRunRow[] = [row({ handlers: ["stale_handler"] })];
    const fresh: LiveDryRunRow[] = [row({ handlers: ["fresh_handler"] })];
    let call = 0;
    const runner: DryRunner = async () => {
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
  test("package.json contributes the toggle command", () => {
    const cmds = pkg().contributes.commands.map((c) => c.command);
    assert.ok(cmds.includes("messagefoundry.toggleLiveDebug"), "toggleLiveDebug command missing");
  });

  test("package.json contributes the debounce config prop", () => {
    const prop = pkg().contributes.configuration.properties["messagefoundry.liveDebug.debounceMs"];
    assert.ok(prop, "liveDebug.debounceMs config prop missing");
    assert.strictEqual(prop.type, "integer");
    assert.strictEqual(prop.default, 400);
  });
});
