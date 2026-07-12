import * as assert from "assert";

import {
  buildElementsView,
  buildFlowView,
  normalize,
  type Graph,
  type VmNode,
} from "../../graphModel";

// Pure (vscode-free) view-model for the CONNECTIONS view (ADR 0091 D2), exercised node-side against
// a canned `graph --json` v2 payload. Covers: the four element sections with each element exactly
// once, fan-in (`fed by` / `receives from`) reference groups, shared-node badges, explicit dynamic
// markers (never a silently shorter list), heuristic-edge labeling, the completed flow chain, and
// the v1-payload normalization fallback.

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

function byLabel(nodes: VmNode[], label: string): VmNode {
  const hit = nodes.find((n) => n.label === label);
  assert.ok(hit, `expected a node labelled '${label}' among [${nodes.map((n) => n.label).join(", ")}]`);
  return hit;
}

function group(el: VmNode, prefix: string): VmNode {
  const hit = el.children.find((c) => c.kind === "refGroup" && c.label.startsWith(prefix));
  assert.ok(hit, `expected a '${prefix}' group under '${el.label}'`);
  return hit;
}

suite("graphModel — elements perspective (ADR 0091 D2)", () => {
  test("four sections, every element exactly once, counts in the description", () => {
    const roots = buildElementsView(V2, "");
    assert.deepStrictEqual(
      roots.map((r) => [r.label, r.description]),
      [
        ["Inbound Connections", "3"],
        ["Routers", "2"],
        ["Handlers", "2"],
        ["Outbound Connections", "2"],
      ],
    );
    const allIds = new Set<string>();
    const walk = (n: VmNode): void => {
      assert.ok(!allIds.has(n.id), `duplicate id ${n.id}`);
      allIds.add(n.id);
      n.children.forEach(walk);
    };
    roots.forEach(walk);
  });

  test("fan-in is visible: shared router lists both inbounds; handler lists both routers", () => {
    const roots = buildElementsView(V2, "");
    const router = byLabel(byLabel(roots, "Routers").children, "route_shared");
    assert.deepStrictEqual(group(router, "⇦ fed by").children.map((r) => r.label), ["IB_A", "IB_B"]);
    assert.ok(router.description?.includes("shared ×2"), router.description);
    const handler = byLabel(byLabel(roots, "Handlers").children, "relay_b");
    assert.deepStrictEqual(group(handler, "⇦ fed by").children.map((r) => r.label), ["route_pt", "route_shared"]);
    assert.ok(handler.description?.includes("shared ×2"));
  });

  test("outbound fan-in + inbound port and router binding are surfaced", () => {
    const roots = buildElementsView(V2, "");
    const ob = byLabel(byLabel(roots, "Outbound Connections").children, "OB_Main");
    assert.deepStrictEqual(group(ob, "⇦ receives from").children.map((r) => r.label), ["relay_b", "xform_main"]);
    const ib = byLabel(byLabel(roots, "Inbound Connections").children, "IB_A");
    assert.strictEqual(ib.description, "mllp :6661 → route_shared");
    assert.strictEqual(ib.contextValue, "meforConnection");
  });

  test("cross-reference rows point at their target element (reveal navigation)", () => {
    const roots = buildElementsView(V2, "");
    const handler = byLabel(byLabel(roots, "Handlers").children, "xform_main");
    const sends = group(handler, "→ sends to").children;
    assert.deepStrictEqual(
      sends.map((r) => [r.elementKind, r.elementName]),
      [
        ["outbound", "OB_Main"],
        ["inbound", "PT_X"],
      ],
    );
    assert.ok(sends[1].description?.includes("pass-through"));
  });

  test("dynamic elements render an explicit marker; heuristic edges are labelled", () => {
    const roots = buildElementsView(V2, "");
    const relay = byLabel(byLabel(roots, "Handlers").children, "relay_b");
    assert.ok(relay.children.some((c) => c.kind === "dynamic"), "expected a dynamic marker");
    const send = group(relay, "→ sends to").children[0];
    assert.ok(send.description?.includes("heuristic"), send.description);
    const routeDyn = byLabel(byLabel(roots, "Routers").children, "route_pt");
    assert.ok(routeDyn.children.some((c) => c.kind === "dynamic"));
  });

  test("the filter narrows to matching elements and hides the sections it emptied", () => {
    const roots = buildElementsView(V2, "relay");
    assert.deepStrictEqual(roots.map((r) => r.label), ["Handlers"]);
    assert.strictEqual(roots[0].children.length, 1);
    assert.deepStrictEqual(buildElementsView(V2, "zzz-no-match"), []);
    assert.strictEqual(buildElementsView(V2, "").length, 4, "no filter keeps all four sections");
  });
});

suite("graphModel — flow perspective (completed chain + badges)", () => {
  test("the chain is completed to the outbound leaves, shared nodes badged", () => {
    const roots = buildFlowView(V2, "", "none");
    const ibA = byLabel(roots, "IB_A");
    const router = ibA.children[0];
    assert.strictEqual(router.label, "route_shared");
    assert.ok(router.description?.includes("shared ×2"));
    const handler = byLabel(router.children, "xform_main");
    assert.deepStrictEqual(
      handler.children.filter((c) => c.kind === "ref").map((c) => c.label),
      ["OB_Main", "PT_X"],
    );
    const relay = byLabel(router.children, "relay_b");
    assert.ok(relay.children.some((c) => c.kind === "dynamic"), "dynamic marker rides into the flow view");
  });

  test("outbound roots stay peers with a fan-in badge; grouping still buckets", () => {
    const roots = buildFlowView(V2, "", "none");
    const ob = byLabel(roots, "OB_Main");
    assert.ok(ob.description?.includes("⇦ 2 handler(s)"), ob.description);
    const grouped = buildFlowView(V2, "", "type");
    assert.ok(grouped.every((g) => g.kind === "group"));
    assert.deepStrictEqual(grouped.map((g) => g.label), ["IB", "OB", "PT"]);
  });
});

suite("graphModel — v1 payload normalization (older CLI)", () => {
  const V1: Graph = {
    inbound: [{ name: "IB_A", type: "mllp", router: "route_x", file: null, line: null }],
    outbound: [{ name: "OB_X", type: "mllp", file: null, line: null }],
    routers: [{ name: "route_x", handlers: ["xform_x"], file: null, line: null }],
    handlers: [{ name: "xform_x", sends: ["OB_X"], file: null, line: null }],
  };

  test("forward lists become heuristic edges and reverse adjacency is derived", () => {
    const n = normalize(V1);
    assert.deepStrictEqual(n.routers.get("route_x")?.fed_by, ["IB_A"]);
    assert.deepStrictEqual(n.handlers.get("xform_x")?.fed_by, ["route_x"]);
    assert.deepStrictEqual(n.outboundReceives.get("OB_X"), ["xform_x"]);
    assert.strictEqual(n.handlers.get("xform_x")?.edges[0]?.provenance, "heuristic");
  });

  test("both perspectives render a v1 payload", () => {
    const el = buildElementsView(V1, "");
    assert.strictEqual(byLabel(el, "Handlers").children.length, 1);
    const flow = buildFlowView(V1, "", "none");
    const chainOut = byLabel(byLabel(flow, "IB_A").children[0].children, "xform_x");
    assert.deepStrictEqual(chainOut.children.map((c) => c.label), ["OB_X"]);
  });
});
