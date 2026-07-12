import * as assert from "assert";

import type { Graph } from "../../graphModel";
import { buildWiringMap, NODE_CAP, type MapNode } from "../../wiringMapModel";

// Pure (vscode-free) view-model for the Wiring Map panel (ADR 0091 D3), exercised node-side like
// graph-model.test.ts. Covers: focus-BFS hop membership (1 vs 2), the four-column assignment
// including the legal handler→inbound pass-through back-edge, provenance passthrough, synthetic
// "?" stubs for dynamic elements, the deterministic 150-node cap on a synthetic 300-element graph
// (+ a rough perf sanity), deterministic barycenter-then-alphabetical row order, and focusMissing.

const V2: Graph = {
  version: 2,
  inbound: [
    { name: "IB_A", type: "mllp", router: "route_shared", settings: { port: 6661 }, file: "/c/a.py", line: 3, receives_from: [] },
    { name: "IB_B", type: "mllp", router: "route_shared", settings: { port: 6662 }, file: "/c/a.py", line: 4, receives_from: [] },
    { name: "PT_X", type: "passthrough", router: "route_pt", file: "/c/a.py", line: 5, receives_from: ["xform_main"] },
  ],
  outbound: [
    { name: "OB_Main", type: "mllp", file: "/c/a.py", line: 6, receives_from: ["relay_b", "xform_main"] },
    { name: "OB_Spare", type: "file", file: "/c/a.py", line: 7, receives_from: [] },
  ],
  routers: [
    {
      name: "route_shared",
      file: "/c/a.py",
      line: 10,
      handlers: ["relay_b", "xform_main"],
      edges: [
        { target: "xform_main", target_kind: "handler", provenance: "literal" },
        { target: "relay_b", target_kind: "handler", provenance: "heuristic" },
      ],
      fed_by: ["IB_A", "IB_B"],
      dynamic: false,
    },
    { name: "route_pt", file: "/c/a.py", line: 20, handlers: [], edges: [], fed_by: ["PT_X"], dynamic: true },
  ],
  handlers: [
    {
      name: "xform_main",
      file: "/c/a.py",
      line: 30,
      sends: ["OB_Main"],
      edges: [
        { target: "OB_Main", target_kind: "outbound", provenance: "literal" },
        { target: "PT_X", target_kind: "inbound", provenance: "literal" },
      ],
      fed_by: ["route_shared"],
      dynamic: false,
    },
    {
      name: "relay_b",
      file: "/c/a.py",
      line: 40,
      sends: ["OB_Main"],
      edges: [{ target: "OB_Main", target_kind: "outbound", provenance: "heuristic" }],
      fed_by: ["route_pt", "route_shared"],
      dynamic: true,
    },
  ],
};

function names(col: MapNode[]): string[] {
  return col.map((n) => n.name);
}

function realNames(col: MapNode[]): string[] {
  return col.filter((n) => !n.stub).map((n) => n.name);
}

suite("wiringMapModel — focus BFS (hop-bounded, both directions)", () => {
  test("hop 1 keeps only the immediate neighborhood", () => {
    const map = buildWiringMap(V2, { kind: "router", name: "route_shared" }, 1);
    assert.strictEqual(map.focusMissing, false);
    assert.deepStrictEqual(realNames(map.columns[0]), ["IB_A", "IB_B"]); // fed-by, upstream direction
    assert.deepStrictEqual(realNames(map.columns[1]), ["route_shared"]);
    assert.deepStrictEqual(realNames(map.columns[2]).sort(), ["relay_b", "xform_main"]);
    assert.deepStrictEqual(realNames(map.columns[3]), [], "outbounds are 2 hops away");
  });

  test("hop 2 widens to the outbounds and the pass-through inbound", () => {
    const map = buildWiringMap(V2, { kind: "router", name: "route_shared" }, 2);
    assert.deepStrictEqual(realNames(map.columns[3]), ["OB_Main"]);
    assert.ok(realNames(map.columns[0]).includes("PT_X"), "PT_X reached via xform_main's pass-through Send");
    assert.ok(!realNames(map.columns[3]).includes("OB_Spare"), "an unwired outbound never rides in");
  });

  test("every element lands in its kind's column; the PT back-edge targets the inbound column", () => {
    const map = buildWiringMap(V2, { kind: "handler", name: "xform_main" }, 2);
    for (const [i, kind] of (["inbound", "router", "handler", "outbound"] as const).entries()) {
      assert.ok(map.columns[i].every((n) => n.kind === kind), `column ${i} holds only ${kind}`);
    }
    assert.ok(realNames(map.columns[0]).includes("PT_X"), "pass-through target renders in the inbound column");
    const back = map.edges.find((e) => e.fromKind === "handler" && e.toKind === "inbound");
    assert.deepStrictEqual(
      back && [back.from, back.to, back.provenance],
      ["xform_main", "PT_X", "literal"],
    );
  });

  test("provenance rides through untouched; inbound→router edges are declared; port surfaces", () => {
    const map = buildWiringMap(V2, { kind: "router", name: "route_shared" }, 2);
    const prov = new Map(map.edges.map((e) => [`${e.from}->${e.to}`, e.provenance]));
    assert.strictEqual(prov.get("IB_A->route_shared"), "declared");
    assert.strictEqual(prov.get("route_shared->xform_main"), "literal");
    assert.strictEqual(prov.get("route_shared->relay_b"), "heuristic");
    assert.strictEqual(prov.get("relay_b->OB_Main"), "heuristic");
    const ibA = map.columns[0].find((n) => n.name === "IB_A");
    assert.strictEqual(ibA?.port, "6661");
    assert.deepStrictEqual(ibA?.open, { file: "/c/a.py", line: 3 });
  });

  test("a dynamic element emits a synthetic '?' stub node + dashed dynamic edge", () => {
    const map = buildWiringMap(V2, { kind: "handler", name: "relay_b" }, 1);
    const stub = map.columns[3].find((n) => n.stub);
    assert.ok(stub, "dynamic handler grows a stub in the outbound column");
    assert.strictEqual(stub?.dynamic, true);
    const stubEdge = map.edges.find((e) => e.from === "relay_b" && e.to === stub?.name);
    assert.strictEqual(stubEdge?.provenance, "dynamic");
    // A dynamic ROUTER's stub lands in the handler column.
    const rmap = buildWiringMap(V2, { kind: "router", name: "route_pt" }, 1);
    assert.ok(rmap.columns[2].some((n) => n.stub), "dynamic router grows a stub in the handler column");
  });

  test("focusMissing on an element the graph no longer has", () => {
    const map = buildWiringMap(V2, { kind: "handler", name: "gone_since_rename" }, 2);
    assert.strictEqual(map.focusMissing, true);
    assert.strictEqual(map.truncated, false);
    assert.deepStrictEqual(map.columns.map((c) => c.length), [0, 0, 0, 0]);
    assert.deepStrictEqual(map.edges, []);
  });
});

suite("wiringMapModel — row order (barycenter over the previous column, then alphabetical)", () => {
  test("rows follow their feeders, not the alphabet; output is deterministic", () => {
    // IB_1 -> r_zzz and IB_2 -> r_aaa: alphabetical would order [r_aaa, r_zzz], but barycenter
    // over the inbound column (IB_1 row 0, IB_2 row 1) must keep r_zzz first (fewer crossings).
    const g: Graph = {
      version: 2,
      inbound: [
        { name: "IB_1", type: "mllp", router: "r_zzz", file: null, line: null },
        { name: "IB_2", type: "mllp", router: "r_aaa", file: null, line: null },
      ],
      outbound: [],
      routers: [
        { name: "r_aaa", edges: [], fed_by: ["IB_2"], file: null, line: null },
        { name: "r_zzz", edges: [], fed_by: ["IB_1"], file: null, line: null },
      ],
      handlers: [],
    };
    // focus=null (whole tiny graph, far under the cap) so BOTH disjoint feeds render at once.
    const map = buildWiringMap(g, null, 3);
    assert.deepStrictEqual(names(map.columns[0]), ["IB_1", "IB_2"], "no previous column -> alphabetical");
    assert.deepStrictEqual(names(map.columns[1]), ["r_zzz", "r_aaa"]);
    assert.deepStrictEqual(map.columns[1].map((n) => n.row), [0, 1]);
    const again = buildWiringMap(g, null, 3);
    assert.deepStrictEqual(again, map, "same input, same map — deterministic");
  });
});

suite("wiringMapModel — node cap (150) and whole-graph mode", () => {
  // A synthetic ~300-element estate: 100 disjoint feeds (inbound -> shared router tiers is not
  // needed — width is what stresses the cap), all reachable from one hub router within 2 hops.
  function bigGraph(): Graph {
    const g: Graph = { version: 2, inbound: [], outbound: [], routers: [], handlers: [] };
    g.routers.push({ name: "hub", edges: [], fed_by: [], file: null, line: null });
    for (let i = 0; i < 100; i++) {
      const nn = String(i).padStart(3, "0");
      g.inbound.push({ name: `IB_${nn}`, type: "mllp", router: "hub", file: null, line: null });
      g.routers[0].fed_by?.push(`IB_${nn}`);
      g.routers[0].edges?.push({ target: `h_${nn}`, target_kind: "handler", provenance: "literal" });
      g.handlers.push({
        name: `h_${nn}`,
        edges: [{ target: `OB_${nn}`, target_kind: "outbound", provenance: "literal" }],
        fed_by: ["hub"],
        file: null,
        line: null,
      });
      g.outbound.push({ name: `OB_${nn}`, type: "file", file: null, line: null });
    }
    return g; // 100 + 1 + 100 + 100 = 301 elements
  }

  test("focus mode caps at 150 nodes, dropping the farthest hop deterministically", () => {
    const g = bigGraph();
    const started = Date.now();
    const map = buildWiringMap(g, { kind: "router", name: "hub" }, 3);
    const elapsed = Date.now() - started;
    assert.strictEqual(map.truncated, true);
    const real = map.columns.flat().filter((n) => !n.stub);
    assert.strictEqual(real.length, NODE_CAP);
    // hop 0 (hub) + hop 1 (100 inbounds + 100 handlers) fills the cap before any hop-2 outbound.
    assert.strictEqual(map.columns[3].length, 0, "farthest hop (outbounds) dropped first");
    assert.deepStrictEqual(names(map.columns[1]), ["hub"]);
    // Deterministic tie-break within the dropped hop: the kept inbounds are the alphabetical head.
    assert.deepStrictEqual(names(map.columns[0]).slice(0, 2), ["IB_000", "IB_001"]);
    assert.ok(elapsed < 1000, `301-element build stayed fast (took ${elapsed}ms)`);
    // Edges never dangle: both endpoints of every edge are rendered nodes.
    const ids = new Set(map.columns.flat().map((n) => `${n.kind}:${n.name}`));
    assert.ok(map.edges.every((e) => ids.has(`${e.fromKind}:${e.from}`) && ids.has(`${e.toKind}:${e.to}`)));
  });

  test("focus=null (whole graph) is legal only because the cap still bounds it", () => {
    const map = buildWiringMap(bigGraph(), null, 2);
    assert.strictEqual(map.truncated, true);
    assert.strictEqual(map.columns.flat().filter((n) => !n.stub).length, NODE_CAP);
    assert.strictEqual(map.focusMissing, false);
  });

  test("a small graph under the cap is complete and untruncated", () => {
    const map = buildWiringMap(V2, null, 2);
    assert.strictEqual(map.truncated, false);
    assert.strictEqual(map.columns.flat().filter((n) => !n.stub).length, 9);
  });
});
