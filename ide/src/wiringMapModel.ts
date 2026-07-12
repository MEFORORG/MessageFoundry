// Pure (vscode-free) view-model for the Wiring Map panel (ADR 0091 D3): a focus-first, hop-bounded,
// node-capped projection of the one wiring graph onto four layout columns — inbound | router |
// handler | outbound, in pipeline order. Strictly READ-ONLY: this is a projection of graphModel's
// normalized graph, never an authoring surface (BACKLOG #26 declined-by-design; the .py stays the
// only artifact and execution path). The whole estate is never rendered by default — the focus BFS
// bounds the subgraph, and focus=null is legal only because the node cap still bounds the render.
// A dynamic element's unresolvable targets become an explicit synthetic "?" stub node + edge, so
// incompleteness is visible, never a silently shorter map (AC-3). Tested node-side like graphModel.

import { normalize, type ElementKind, type Graph, type NormalGraph } from "./graphModel";

export type MapProvenance = "declared" | "literal" | "heuristic" | "dynamic";

export interface MapFocus {
  kind: ElementKind;
  name: string;
}

export interface MapNode {
  kind: ElementKind;
  name: string;
  /** Layout row within the kind's column (barycenter-then-alphabetical, deterministic). */
  row: number;
  dynamic: boolean;
  /** Inbound only: the uniquely-owned port, when configured. */
  port?: string;
  /** Element rows: double-click opens the definition. Absent on stubs / location-less elements. */
  open?: { file: string; line: number };
  /** Synthetic "?" placeholder standing in for a dynamic element's unresolvable targets. */
  stub?: boolean;
}

export interface MapEdge {
  fromKind: ElementKind;
  from: string;
  toKind: ElementKind;
  to: string;
  provenance: MapProvenance;
}

export interface WiringMap {
  /** inbound | router | handler | outbound, in pipeline order. */
  columns: [MapNode[], MapNode[], MapNode[], MapNode[]];
  edges: MapEdge[];
  /** True when the node cap dropped nodes (farthest hop dropped first, deterministically). */
  truncated: boolean;
  /** True when the requested focus element is not in the graph (renamed/removed since). */
  focusMissing: boolean;
}

export const NODE_CAP = 150;
// The Wiring Map always renders at the maximum hop depth — there is no user-facing hop control;
// the node cap (NODE_CAP) is what bounds the render. Single source for buildWiringMap's depth.
export const MAX_HOPS = 3;

/** Column index per kind — also the layout's left-to-right pipeline order. */
const COL: Record<ElementKind, number> = { inbound: 0, router: 1, handler: 2, outbound: 3 };

interface FlatElement {
  kind: ElementKind;
  name: string;
  dynamic: boolean;
  port?: string;
  open?: { file: string; line: number };
}

function opened(loc: { file?: string | null; line?: number | null }): { file: string; line: number } | undefined {
  return loc.file ? { file: loc.file, line: loc.line ?? 1 } : undefined;
}

function elementId(kind: ElementKind, name: string): string {
  return `${kind}:${name}`;
}

/** Every element of the graph, flattened to what a map node needs, keyed `kind:name`. */
function collectElements(n: NormalGraph): Map<string, FlatElement> {
  const out = new Map<string, FlatElement>();
  for (const c of n.inbound.values()) {
    const p = c.settings?.["port"];
    out.set(elementId("inbound", c.name), {
      kind: "inbound",
      name: c.name,
      dynamic: false,
      port: typeof p === "number" || typeof p === "string" ? String(p) : undefined,
      open: opened(c),
    });
  }
  for (const r of n.routers.values()) {
    out.set(elementId("router", r.name), { kind: "router", name: r.name, dynamic: !!r.dynamic, open: opened(r) });
  }
  for (const h of n.handlers.values()) {
    out.set(elementId("handler", h.name), { kind: "handler", name: h.name, dynamic: !!h.dynamic, open: opened(h) });
  }
  for (const o of n.outbound.values()) {
    out.set(elementId("outbound", o.name), { kind: "outbound", name: o.name, dynamic: false, open: opened(o) });
  }
  return out;
}

/** Every statically-known edge, provenance carried through; targets that resolve to no known
 *  element are omitted here (the element's `dynamic` flag + stub covers unresolvables). A
 *  handler→inbound pass-through edge is legal and kept — its target lays out in the inbound column. */
function collectEdges(n: NormalGraph): MapEdge[] {
  const edges: MapEdge[] = [];
  const seen = new Set<string>();
  const push = (fromKind: ElementKind, from: string, toKind: ElementKind, to: string, provenance: MapProvenance): void => {
    const key = `${fromKind}:${from}->${toKind}:${to}`;
    if (!seen.has(key)) {
      seen.add(key);
      edges.push({ fromKind, from, toKind, to, provenance });
    }
  };
  for (const c of n.inbound.values()) {
    if (n.routers.has(c.router)) {
      push("inbound", c.name, "router", c.router, "declared");
    }
  }
  for (const r of n.routers.values()) {
    for (const e of r.edges) {
      if (e.target_kind === "handler" && n.handlers.has(e.target)) {
        push("router", r.name, "handler", e.target, e.provenance);
      }
    }
  }
  for (const h of n.handlers.values()) {
    for (const e of h.edges) {
      if (e.target_kind === "outbound" && n.outbound.has(e.target)) {
        push("handler", h.name, "outbound", e.target, e.provenance);
      } else if (e.target_kind === "inbound" && n.inbound.has(e.target)) {
        push("handler", h.name, "inbound", e.target, e.provenance);
      }
    }
  }
  return edges;
}

export function buildWiringMap(g: Graph, focus: MapFocus | null, hops: number = MAX_HOPS): WiringMap {
  const n = normalize(g);
  const elements = collectElements(n);
  const rawEdges = collectEdges(n);

  if (focus && !elements.has(elementId(focus.kind, focus.name))) {
    return { columns: [[], [], [], []], edges: [], truncated: false, focusMissing: true };
  }

  // Hop distance from the focus: BFS over the UNDIRECTED adjacency (fan-in matters as much as
  // fan-out; pass-through back-edges ride along). focus=null keeps every element at hop 0 — legal
  // only because the cap below still bounds the render, never the whole estate by accident.
  const hop = new Map<string, number>();
  if (focus) {
    const adj = new Map<string, string[]>();
    const link = (a: string, b: string): void => {
      const cur = adj.get(a);
      if (cur) {
        cur.push(b);
      } else {
        adj.set(a, [b]);
      }
    };
    for (const e of rawEdges) {
      const a = elementId(e.fromKind, e.from);
      const b = elementId(e.toKind, e.to);
      link(a, b);
      link(b, a);
    }
    const start = elementId(focus.kind, focus.name);
    hop.set(start, 0);
    let frontier = [start];
    for (let d = 1; d <= hops && frontier.length > 0; d++) {
      const next: string[] = [];
      for (const cur of frontier) {
        for (const nb of adj.get(cur) ?? []) {
          if (!hop.has(nb)) {
            hop.set(nb, d);
            next.push(nb);
          }
        }
      }
      frontier = next;
    }
  } else {
    for (const key of elements.keys()) {
      hop.set(key, 0);
    }
  }

  // Deterministic node cap: keep the nearest nodes, ties broken by column order then name — so the
  // farthest-hop fringe is what drops, and the same graph always renders the same map.
  let ids = [...hop.keys()];
  ids.sort((a, b) => {
    const dh = (hop.get(a) ?? 0) - (hop.get(b) ?? 0);
    if (dh !== 0) {
      return dh;
    }
    const ea = elements.get(a);
    const eb = elements.get(b);
    if (!ea || !eb) {
      return a.localeCompare(b);
    }
    return COL[ea.kind] - COL[eb.kind] || ea.name.localeCompare(eb.name);
  });
  const truncated = ids.length > NODE_CAP;
  if (truncated) {
    ids = ids.slice(0, NODE_CAP);
  }
  const kept = new Set(ids);

  const edges = rawEdges.filter(
    (e) => kept.has(elementId(e.fromKind, e.from)) && kept.has(elementId(e.toKind, e.to)),
  );

  const columns: [MapNode[], MapNode[], MapNode[], MapNode[]] = [[], [], [], []];
  for (const key of ids) {
    const el = elements.get(key);
    if (!el) {
      continue;
    }
    const node: MapNode = { kind: el.kind, name: el.name, row: 0, dynamic: el.dynamic };
    if (el.port !== undefined) {
      node.port = el.port;
    }
    if (el.open) {
      node.open = el.open;
    }
    columns[COL[el.kind]].push(node);
    // A dynamic element's unresolved targets are made VISIBLE: a synthetic "?" stub in the next
    // column, wired by a dashed dynamic edge — never a silently shorter map (AC-3).
    if (el.dynamic && (el.kind === "router" || el.kind === "handler")) {
      const toKind: ElementKind = el.kind === "router" ? "handler" : "outbound";
      const stubName = `? ${el.name}`;
      columns[COL[toKind]].push({ kind: toKind, name: stubName, row: 0, dynamic: true, stub: true });
      edges.push({ fromKind: el.kind, from: el.name, toKind, to: stubName, provenance: "dynamic" });
    }
  }

  // Row order per column: barycenter over the previous column's rows (crossing reduction, one
  // left-to-right sweep) then alphabetical; neighbor-less nodes sink below, alphabetically.
  // Column 0 has no previous column, so it is purely alphabetical. Deterministic throughout.
  for (let col = 0; col < 4; col++) {
    const nodes = columns[col];
    const bary = new Map<string, number>();
    if (col > 0) {
      const prevRow = new Map(columns[col - 1].map((p) => [p.name, p.row]));
      for (const node of nodes) {
        const rows: number[] = [];
        for (const e of edges) {
          if (COL[e.fromKind] === col - 1 && COL[e.toKind] === col && e.to === node.name) {
            const r = prevRow.get(e.from);
            if (r !== undefined) {
              rows.push(r);
            }
          } else if (COL[e.toKind] === col - 1 && COL[e.fromKind] === col && e.from === node.name) {
            const r = prevRow.get(e.to);
            if (r !== undefined) {
              rows.push(r);
            }
          }
        }
        if (rows.length > 0) {
          bary.set(node.name, rows.reduce((s, v) => s + v, 0) / rows.length);
        }
      }
    }
    nodes.sort((a, b) => {
      const ba = bary.get(a.name);
      const bb = bary.get(b.name);
      if (ba !== undefined && bb !== undefined && ba !== bb) {
        return ba - bb;
      }
      if ((ba === undefined) !== (bb === undefined)) {
        return ba === undefined ? 1 : -1;
      }
      return a.name.localeCompare(b.name);
    });
    nodes.forEach((node, i) => {
      node.row = i;
    });
  }

  // Deterministic edge order too, so the SVG (and any test snapshot) is stable.
  edges.sort(
    (a, b) =>
      COL[a.fromKind] - COL[b.fromKind] ||
      a.from.localeCompare(b.from) ||
      COL[a.toKind] - COL[b.toKind] ||
      a.to.localeCompare(b.to),
  );

  return { columns, edges, truncated, focusMissing: false };
}
