// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 MessageFoundry Organization and contributors
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
import {
  buildRuntimeMap,
  CONNECTIONS_ROUTE,
  LIVE_STATUS_PLAN,
  type ConnectionRowLite,
} from "../../liveStatusModel";

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

suite("liveStatus poll — the timer may not carry a bearer (AUTH-IDLE / CWE-613)", () => {
  const LIVE_STATUS_TS = path.join(__dirname, "..", "..", "..", "src", "liveStatus.ts");

  test("LIVE_STATUS_PLAN is tokenless, and names the one route this feature reads", () => {
    // This is the control, not the file header above it. `GET /connections` is gated by plain
    // `require(Permission.MONITORING_READ)`, and `require()` resolves the bearer with
    // `identity_for_token(bearer_token(request))` — the default `activity=True`, which refreshes
    // the session's idle clock. So a bearer on this 5-to-10-second
    // timer would keep the session alive for as long as a VS Code window stays open and make the
    // engine's 30-minute idle timeout unreachable, on the exact client the automatic-logoff control
    // exists for. liveStatus.poll attaches the token IFF the plan entry says `authenticated`, so
    // this assertion is what actually holds the line. Same rule, same shape, as POLL_PLAN.
    assert.ok(LIVE_STATUS_PLAN.length > 0);
    for (const entry of LIVE_STATUS_PLAN) {
      assert.strictEqual(
        entry.authenticated,
        false,
        `the live-status poll must not authenticate (${entry.route}) — it would defeat AUTH-IDLE`,
      );
    }
    assert.deepStrictEqual(
      LIVE_STATUS_PLAN.map((e) => e.route),
      [CONNECTIONS_ROUTE],
    );
    assert.strictEqual(CONNECTIONS_ROUTE, "/connections");
  });

  test("the poll's call site reads the token ONLY through the plan", () => {
    // The plan is a control only if the shell obeys it, so read the shell. A source scan that
    // silently matches nothing is indistinguishable from a clean file, hence the guards below.
    const text = fs.readFileSync(LIVE_STATUS_TS, "utf8");
    assert.ok(
      text.includes("getJson<ConnectionRowLite[]>("),
      "the poll's call site moved — re-point this scan before trusting it",
    );
    const sites = text.split(/\r?\n/).filter((l) => l.includes("peekToken("));
    assert.strictEqual(sites.length, 1, `expected one peekToken call site, found ${sites.length}`);
    assert.ok(
      /entry\.authenticated \?/.test(sites[0]),
      `the poll must resolve its bearer through the plan, not unconditionally: ${sites[0].trim()}`,
    );

    // The check must be able to give a DIFFERENT answer. This is the line the file actually carried
    // before the fix; if the predicate accepts it, the predicate is not testing anything.
    const defect = "        const bearer = await peekToken(this.ctx, url);";
    assert.ok(defect.includes("peekToken("), "the control line does not even reach the predicate");
    assert.ok(
      !/entry\.authenticated \?/.test(defect),
      "the predicate passes the defect it exists to catch",
    );
  });

  test("a tokenless 401 does not clear the cached session", () => {
    // The poll sends no bearer, so a 401 means "this route needs auth" — never "your session died".
    // Clearing on it would sign the user out from a timer, over a request their session had no part
    // in. auth.withAuth still clears on a 401 from a request that DID carry the token.
    const text = fs.readFileSync(LIVE_STATUS_TS, "utf8");
    assert.ok(text.includes("peekToken"), "vacuity guard: this file should still name auth at all");
    assert.ok(
      !text.includes("clearToken"),
      "liveStatus must not clear a token from a background timer",
    );
  });

  test("a tokenless 401 STANDS THE TIMER DOWN rather than retrying for the life of the window", () => {
    // Dropping the bearer made this failure DETERMINISTIC: LIVE_STATUS_PLAN is a compile-time
    // constant with authenticated:false, so against an auth-enabled engine every tick 401s and no
    // amount of waiting changes it. Left running that is one guaranteed-waste request every
    // intervalMs, forever — 360-720/hour per open window. applySettings() re-arms, which is the only
    // thing that can change the answer.
    const text = fs.readFileSync(LIVE_STATUS_TS, "utf8");
    assert.ok(
      text.includes("standDown"),
      "vacuity guard: the stand-down path must exist in the shell at all",
    );
    assert.ok(
      /e\.status === 401 && !entry\.authenticated/.test(text),
      "the stand-down must be gated on a TOKENLESS 401 — an authenticated 401 is a dead session, " +
        "which is a different fact and must not silently stop the poller",
    );
    assert.ok(
      /clearInterval/.test(text.slice(text.indexOf("private standDown"))),
      "standDown must actually clear the interval, not merely mark a flag",
    );
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
