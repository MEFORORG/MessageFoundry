import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

import {
  buildElementsView,
  formatCount,
  runtimeEquals,
  runtimeKey,
  runtimeSuffix,
  type Graph,
  type RuntimeInfo,
  type VmNode,
} from "../../graphModel";
import { buildRuntimeMap, type ConnectionRowLite } from "../../liveStatusModel";

// Live decorations for the CONNECTIONS view (ADR 0091 "live decorations"), exercised vscode-free:
// the pure reduction of the engine's `GET /connections` rows into a RuntimeMap, and the
// description-suffix enrichment buildElementsView applies from it. Status words + counts only —
// the payload subset consumed here carries no message content by construction.

function row(partial: Partial<ConnectionRowLite>): ConnectionRowLite {
  return { role: "source", channel_id: "IB_A", status: "running", ...partial };
}

suite("liveStatusModel — buildRuntimeMap", () => {
  test("a source row maps to its inbound element", () => {
    const map = buildRuntimeMap([row({ read: 1234, errored: 0 })]);
    assert.deepStrictEqual(map.get(runtimeKey("inbound", "IB_A")), {
      status: "running",
      count: 1234,
      errored: 0,
    });
  });

  test("destination rows AGGREGATE per outbound: counts sum, worst status wins", () => {
    // /connections emits one destination row per (inbound → outbound) EDGE; the tree has one
    // outbound element, so a failed lane must not hide behind a healthy sibling.
    const map = buildRuntimeMap([
      row({ role: "destination", channel_id: "IB_A", destination: "OB_X", status: "running", written: 700, errored: 1 }),
      row({ role: "destination", channel_id: "IB_B", destination: "OB_X", status: "failed", written: 500, errored: 2 }),
    ]);
    assert.deepStrictEqual(map.get(runtimeKey("outbound", "OB_X")), {
      status: "failed",
      count: 1200,
      errored: 3,
    });
  });

  test("an unknown status word never masks a known-bad one, but renders alone", () => {
    const both = buildRuntimeMap([
      row({ role: "destination", destination: "OB_X", status: "hyperdrive", written: 1 }),
      row({ role: "destination", destination: "OB_X", status: "stopped", written: 1 }),
    ]);
    assert.strictEqual(both.get(runtimeKey("outbound", "OB_X"))?.status, "stopped");
    const alone = buildRuntimeMap([row({ role: "destination", destination: "OB_X", status: "hyperdrive" })]);
    assert.strictEqual(alone.get(runtimeKey("outbound", "OB_X"))?.status, "hyperdrive");
  });

  test("null/missing counts and malformed rows degrade, never throw", () => {
    const map = buildRuntimeMap([
      row({ read: null, errored: null }),
      row({ role: "destination", destination: null, status: "running" }), // no join key → skipped
      row({ role: "destination", destination: "OB_X", written: null }),
    ]);
    assert.deepStrictEqual(map.get(runtimeKey("inbound", "IB_A")), {
      status: "running",
      count: undefined,
      errored: undefined,
    });
    assert.deepStrictEqual(map.get(runtimeKey("outbound", "OB_X")), {
      status: "running",
      count: undefined,
      errored: undefined,
    });
    assert.strictEqual(map.size, 2);
  });
});

suite("graphModel — runtime suffix rendering", () => {
  test("formatCount is compact", () => {
    assert.strictEqual(formatCount(0), "0");
    assert.strictEqual(formatCount(987), "987");
    assert.strictEqual(formatCount(1234), "1.2k");
    assert.strictEqual(formatCount(20000), "20k");
    assert.strictEqual(formatCount(1_234_567), "1.2M");
  });

  test("runtimeSuffix shows status, count, and errors-only-when-nonzero", () => {
    assert.strictEqual(runtimeSuffix(undefined), "");
    assert.strictEqual(runtimeSuffix({ status: "running", count: 1234 }), " · running · 1.2k");
    assert.strictEqual(runtimeSuffix({ status: "failed" }), " · failed");
    assert.strictEqual(
      runtimeSuffix({ status: "running", count: 10, errored: 2 }),
      " · running · 10 · 2 err",
    );
    assert.strictEqual(runtimeSuffix({ status: "running", count: 10, errored: 0 }), " · running · 10");
  });

  test("runtimeEquals: same picture → equal; any drift → not", () => {
    const a = new Map<string, RuntimeInfo>([["inbound:IB_A", { status: "running", count: 1 }]]);
    const b = new Map<string, RuntimeInfo>([["inbound:IB_A", { status: "running", count: 1 }]]);
    assert.ok(runtimeEquals(a, b));
    assert.ok(runtimeEquals(undefined, undefined));
    assert.ok(!runtimeEquals(a, undefined));
    assert.ok(!runtimeEquals(a, new Map([["inbound:IB_A", { status: "running", count: 2 }]])));
    assert.ok(!runtimeEquals(a, new Map([["inbound:IB_B", { status: "running", count: 1 }]])));
  });
});

suite("graphModel — elements view runtime enrichment", () => {
  const G: Graph = {
    version: 2,
    inbound: [
      { name: "IB_A", type: "mllp", router: "route_x", settings: { port: 6661 }, file: "/c/a.py", line: 3 },
    ],
    outbound: [{ name: "OB_X", type: "mllp", file: "/c/a.py", line: 6 }],
    routers: [{ name: "route_x", handlers: ["h_x"], file: "/c/a.py", line: 10 }],
    handlers: [{ name: "h_x", sends: ["OB_X"], file: "/c/a.py", line: 30 }],
  };

  function el(roots: VmNode[], section: string, name: string): VmNode {
    const sec = roots.find((r) => r.label === section);
    assert.ok(sec, `section ${section} missing`);
    const found = sec.children.find((c) => c.label === name);
    assert.ok(found, `element ${name} missing`);
    return found;
  }

  test("inbound and outbound rows gain a status/count suffix from the runtime map", () => {
    const runtime = new Map<string, RuntimeInfo>([
      [runtimeKey("inbound", "IB_A"), { status: "running", count: 1234 }],
      [runtimeKey("outbound", "OB_X"), { status: "failed", count: 7, errored: 7 }],
    ]);
    const roots = buildElementsView(G, "", runtime);
    assert.strictEqual(
      el(roots, "Inbound Connections", "IB_A").description,
      "mllp :6661 → route_x · running · 1.2k",
    );
    assert.strictEqual(
      el(roots, "Outbound Connections", "OB_X").description,
      "mllp · failed · 7 · 7 err",
    );
    // Routers/handlers stay undecorated — the engine has no per-router/handler counters.
    assert.strictEqual(el(roots, "Routers", "route_x").description, "router");
  });

  test("no runtime map (or no entry for an element) leaves descriptions exactly as before", () => {
    const bare = buildElementsView(G, "");
    assert.strictEqual(el(bare, "Inbound Connections", "IB_A").description, "mllp :6661 → route_x");
    const partial = buildElementsView(
      G,
      "",
      new Map<string, RuntimeInfo>([[runtimeKey("outbound", "OB_X"), { status: "running" }]]),
    );
    assert.strictEqual(el(partial, "Inbound Connections", "IB_A").description, "mllp :6661 → route_x");
    assert.strictEqual(el(partial, "Outbound Connections", "OB_X").description, "mllp · running");
  });
});

suite("liveStatus contributions", () => {
  interface Pkg {
    version: string;
    contributes: {
      configuration: { properties: Record<string, { type?: string; default?: unknown; minimum?: number }> };
    };
  }

  function pkg(): Pkg {
    return JSON.parse(
      fs.readFileSync(path.join(__dirname, "..", "..", "..", "package.json"), "utf8"),
    ) as Pkg;
  }

  test("package.json contributes liveStatus.enabled (default OFF) and intervalSeconds (min 5)", () => {
    const props = pkg().contributes.configuration.properties;
    const enabled = props["messagefoundry.liveStatus.enabled"];
    assert.ok(enabled, "liveStatus.enabled config prop missing");
    assert.strictEqual(enabled.type, "boolean");
    assert.strictEqual(enabled.default, false, "live status must be opt-in");
    const interval = props["messagefoundry.liveStatus.intervalSeconds"];
    assert.ok(interval, "liveStatus.intervalSeconds config prop missing");
    assert.strictEqual(interval.type, "integer");
    assert.strictEqual(interval.default, 10);
    assert.strictEqual(interval.minimum, 5);
  });
});
