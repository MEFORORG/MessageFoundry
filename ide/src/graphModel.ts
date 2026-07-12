// Pure (vscode-free) view-model for the CONNECTIONS view (ADR 0091 D2). Two perspectives over the
// one wiring graph the `graph --json` CLI emits (v2: provenanced edges + reverse adjacency):
//
//  - "elements" (default): four flat sections — INBOUND / ROUTERS / HANDLERS / OUTBOUND — each
//    element exactly once, expanding to navigable `fed by` / `sends to` cross-reference children
//    (the by-name reference pattern; fan-in is always visible, nothing implies containment).
//  - "flow": the legacy inbound → router → handler → outbound chain, completed to the outbound
//    leaves, with every shared node badged (`shared ×N`) so duplication reads as reference.
//
// An element whose targets are not statically resolvable renders an explicit dynamic marker —
// never a silently shorter list (AC-3). Tested node-side (no vscode import) like stepsModel.

export interface Located {
  file?: string | null;
  line?: number | null;
}

export interface GraphEdge {
  target: string;
  target_kind: string;
  provenance: "declared" | "literal" | "heuristic";
}

export interface Graph {
  version?: number;
  inbound: ({
    name: string;
    type: string;
    router: string;
    settings?: Record<string, unknown>;
    receives_from?: string[];
  } & Located)[];
  outbound: ({
    name: string;
    type: string;
    settings?: Record<string, unknown>;
    receives_from?: string[];
  } & Located)[];
  routers: ({
    name: string;
    handlers?: string[];
    edges?: GraphEdge[];
    fed_by?: string[];
    dynamic?: boolean;
  } & Located)[];
  handlers: ({
    name: string;
    sends?: string[];
    edges?: GraphEdge[];
    fed_by?: string[];
    dynamic?: boolean;
  } & Located)[];
}

export type Perspective = "elements" | "flow";
export type GroupingMode = "none" | "type" | "partner";

export type ElementKind = "inbound" | "router" | "handler" | "outbound";

/** One renderable row. `id` is unique across the whole tree (flow paths repeat elements). */
export interface VmNode {
  id: string;
  label: string;
  kind: "section" | "element" | "refGroup" | "ref" | "dynamic" | "group" | "info";
  description?: string;
  icon?: string;
  contextValue?: string;
  collapsible: "none" | "collapsed" | "expanded";
  children: VmNode[];
  /** element/ref rows: what they are / point at (ref click = reveal this element). */
  elementKind?: ElementKind;
  elementName?: string;
  /** element rows: click opens the definition. */
  open?: { file: string; line: number };
}

const DYNAMIC_LABEL = "(dynamic — target not statically resolvable)";

// ---------------------------------------------------------------------------
// Live runtime decorations (ADR 0091 "live decorations" follow-through)
// ---------------------------------------------------------------------------
// The engine's `GET /connections` feeds a per-connection runtime map; inbound/outbound element
// rows render it as a description suffix. Status words + counts ONLY — never message content
// (PHI rule). Routers/handlers carry no suffix: the engine keys its stage metrics by connection,
// so there is no per-router/handler counter to show.

/** Live runtime facts for ONE connection: the engine status word (running/stopped/failed/filtered/
 *  draining/stopping), the message count (inbound: received; outbound: delivered), and errors
 *  (inbound: errored; outbound: dead-lettered). */
export interface RuntimeInfo {
  status: string;
  count?: number;
  errored?: number;
}

/** connKey(kind, name) → RuntimeInfo, for the two decorated kinds. */
export type RuntimeMap = ReadonlyMap<string, RuntimeInfo>;

export function runtimeKey(kind: "inbound" | "outbound", name: string): string {
  return `${kind}:${name}`;
}

/** Compact count for a tree-row suffix: 987 → "987", 1234 → "1.2k", 12_345_678 → "12.3M". */
export function formatCount(n: number): string {
  const scaled = (v: number, unit: string): string => {
    const one = Math.round(v * 10) / 10;
    return `${Number.isInteger(one) ? one.toFixed(0) : one.toFixed(1)}${unit}`;
  };
  if (n < 1000) {
    return String(n);
  }
  if (n < 1_000_000) {
    return scaled(n / 1000, "k");
  }
  return scaled(n / 1_000_000, "M");
}

/** The description suffix for a decorated row, e.g. " · running · 1.2k" or " · failed · 3 err";
 *  empty when there is no live data for the element (undecorated is the honest default). */
export function runtimeSuffix(info: RuntimeInfo | undefined): string {
  if (!info) {
    return "";
  }
  const parts = [info.status];
  if (typeof info.count === "number") {
    parts.push(formatCount(info.count));
  }
  if (typeof info.errored === "number" && info.errored > 0) {
    parts.push(`${formatCount(info.errored)} err`);
  }
  return ` · ${parts.join(" · ")}`;
}

/** Structural equality of two runtime maps — the tree provider skips an invalidate (and the row
 *  flicker it causes) when a poll returns the same picture. */
export function runtimeEquals(a: RuntimeMap | undefined, b: RuntimeMap | undefined): boolean {
  if (a === b) {
    return true;
  }
  if (!a || !b || a.size !== b.size) {
    return false;
  }
  for (const [key, va] of a) {
    const vb = b.get(key);
    if (!vb || va.status !== vb.status || va.count !== vb.count || va.errored !== vb.errored) {
      return false;
    }
  }
  return true;
}

function opened(loc: Located): { file: string; line: number } | undefined {
  return loc.file ? { file: loc.file, line: loc.line ?? 1 } : undefined;
}

function port(settings: Record<string, unknown> | undefined): string {
  const p = settings?.["port"];
  return typeof p === "number" || typeof p === "string" ? ` :${p}` : "";
}

// Group keys parsed from the [TYPE]_[PARTNER]_[MESSAGE] convention name.
export function typeCode(name: string): string {
  const i = name.indexOf("_");
  return i > 0 ? name.slice(0, i) : "(other)";
}

export function partnerName(name: string): string {
  const parts = name.split("_");
  return parts.length >= 2 && parts[1] ? parts[1] : "(none)";
}

/** The graph with v2 edges/fan-in guaranteed: a v1 payload (older CLI) is normalized client-side
 *  (forward name lists become heuristic edges; reverse adjacency is derived), so both perspectives
 *  render from one shape. */
export interface NormalGraph {
  inbound: Map<string, Graph["inbound"][number]>;
  outbound: Map<string, Graph["outbound"][number]>;
  routers: Map<string, Graph["routers"][number] & { edges: GraphEdge[]; fed_by: string[] }>;
  handlers: Map<string, Graph["handlers"][number] & { edges: GraphEdge[]; fed_by: string[] }>;
  outboundReceives: Map<string, string[]>;
  inboundReceives: Map<string, string[]>;
}

export function normalize(g: Graph): NormalGraph {
  const routers = new Map<string, Graph["routers"][number] & { edges: GraphEdge[]; fed_by: string[] }>();
  for (const r of g.routers) {
    const edges =
      r.edges ?? (r.handlers ?? []).map((h): GraphEdge => ({ target: h, target_kind: "handler", provenance: "heuristic" }));
    const fed_by = r.fed_by ?? g.inbound.filter((c) => c.router === r.name).map((c) => c.name);
    routers.set(r.name, { ...r, edges, fed_by: [...fed_by].sort() });
  }
  const handlers = new Map<string, Graph["handlers"][number] & { edges: GraphEdge[]; fed_by: string[] }>();
  for (const h of g.handlers) {
    const edges =
      h.edges ?? (h.sends ?? []).map((s): GraphEdge => ({ target: s, target_kind: "outbound", provenance: "heuristic" }));
    const fed_by =
      h.fed_by ??
      [...routers.values()].filter((r) => r.edges.some((e) => e.target_kind === "handler" && e.target === h.name)).map((r) => r.name);
    handlers.set(h.name, { ...h, edges, fed_by: [...fed_by].sort() });
  }
  const outboundReceives = new Map<string, string[]>();
  const inboundReceives = new Map<string, string[]>();
  for (const o of g.outbound) {
    outboundReceives.set(o.name, o.receives_from ?? []);
  }
  for (const c of g.inbound) {
    inboundReceives.set(c.name, c.receives_from ?? []);
  }
  // Derive reverse adjacency when the CLI didn't provide it (v1 payload).
  for (const h of handlers.values()) {
    for (const e of h.edges) {
      const bucket = e.target_kind === "outbound" ? outboundReceives : e.target_kind === "inbound" ? inboundReceives : undefined;
      if (bucket) {
        const cur = bucket.get(e.target) ?? [];
        if (!cur.includes(h.name)) {
          bucket.set(e.target, [...cur, h.name].sort());
        }
      }
    }
  }
  return {
    inbound: new Map(g.inbound.map((c) => [c.name, c])),
    outbound: new Map(g.outbound.map((o) => [o.name, o])),
    routers,
    handlers,
    outboundReceives,
    inboundReceives,
  };
}

function shared(count: number): string {
  return count > 1 ? ` · shared ×${count}` : "";
}

function ref(id: string, kind: ElementKind, name: string, description: string): VmNode {
  const icons: Record<ElementKind, string> = {
    inbound: "arrow-right",
    router: "git-branch",
    handler: "symbol-method",
    outbound: "arrow-up",
  };
  return {
    id,
    label: name,
    kind: "ref",
    description,
    icon: icons[kind],
    collapsible: "none",
    children: [],
    elementKind: kind,
    elementName: name,
  };
}

function refGroup(id: string, label: string, refs: VmNode[]): VmNode[] {
  if (refs.length === 0) {
    return [];
  }
  return [
    {
      id,
      label: `${label} (${refs.length})`,
      kind: "refGroup",
      icon: label.startsWith("⇦") ? "arrow-small-left" : "arrow-small-right",
      collapsible: "expanded",
      children: refs,
    },
  ];
}

function dynamicMarker(id: string): VmNode {
  return {
    id,
    label: DYNAMIC_LABEL,
    kind: "dynamic",
    icon: "question",
    collapsible: "none",
    children: [],
  };
}

function sendRefs(idPrefix: string, edges: GraphEdge[]): VmNode[] {
  return edges
    .filter((e) => e.target_kind === "outbound" || e.target_kind === "inbound")
    .sort((a, b) => a.target.localeCompare(b.target))
    .map((e) => {
      const kind: ElementKind = e.target_kind === "outbound" ? "outbound" : "inbound";
      const passThrough = e.target_kind === "inbound" ? "pass-through " : "";
      const heuristic = e.provenance === "heuristic" ? " · heuristic" : "";
      return ref(`${idPrefix}/${e.target_kind}:${e.target}`, kind, e.target, `${passThrough}${kind}${heuristic}`);
    });
}

// ---------------------------------------------------------------------------
// Elements perspective
// ---------------------------------------------------------------------------

function section(id: string, label: string, children: VmNode[]): VmNode {
  return {
    id,
    label,
    kind: "section",
    description: String(children.length),
    icon: "folder",
    collapsible: "expanded",
    children,
  };
}

export function buildElementsView(g: Graph, filter: string, runtime?: RuntimeMap): VmNode[] {
  const n = normalize(g);
  const f = filter.trim().toLowerCase();
  const keep = (name: string): boolean => !f || name.toLowerCase().includes(f);

  const inbound = [...n.inbound.values()]
    .filter((c) => keep(c.name))
    .sort((a, b) => a.name.localeCompare(b.name))
    .map((c): VmNode => {
      const id = `el:inbound:${c.name}`;
      const receives = n.inboundReceives.get(c.name) ?? [];
      return {
        id,
        label: c.name,
        kind: "element",
        description: `${c.type}${port(c.settings)} → ${c.router}${runtimeSuffix(runtime?.get(runtimeKey("inbound", c.name)))}`,
        icon: "arrow-right",
        contextValue: "meforConnection",
        collapsible: "collapsed",
        elementKind: "inbound",
        elementName: c.name,
        open: opened(c),
        children: [
          ref(`${id}/router`, "router", c.router, "router"),
          ...refGroup(
            `${id}/receives`,
            "⇦ receives from",
            receives.map((h) => ref(`${id}/receives/${h}`, "handler", h, "handler · pass-through Send")),
          ),
        ],
      };
    });

  const routers = [...n.routers.values()]
    .filter((r) => keep(r.name))
    .sort((a, b) => a.name.localeCompare(b.name))
    .map((r): VmNode => {
      const id = `el:router:${r.name}`;
      const handlerRefs = r.edges
        .filter((e) => e.target_kind === "handler")
        .sort((a, b) => a.target.localeCompare(b.target))
        .map((e) =>
          ref(`${id}/to/${e.target}`, "handler", e.target, `handler${e.provenance === "heuristic" ? " · heuristic" : ""}`),
        );
      return {
        id,
        label: r.name,
        kind: "element",
        description: `router${shared(r.fed_by.length)}`,
        icon: "git-branch",
        contextValue: "meforElement",
        collapsible: "collapsed",
        elementKind: "router",
        elementName: r.name,
        open: opened(r),
        children: [
          ...refGroup(`${id}/fed`, "⇦ fed by", r.fed_by.map((i) => ref(`${id}/fed/${i}`, "inbound", i, "inbound"))),
          ...refGroup(`${id}/to`, "→ sends to", handlerRefs),
          ...(r.dynamic ? [dynamicMarker(`${id}/dynamic`)] : []),
        ],
      };
    });

  const handlers = [...n.handlers.values()]
    .filter((h) => keep(h.name))
    .sort((a, b) => a.name.localeCompare(b.name))
    .map((h): VmNode => {
      const id = `el:handler:${h.name}`;
      return {
        id,
        label: h.name,
        kind: "element",
        description: `handler${shared(h.fed_by.length)}`,
        icon: "symbol-method",
        contextValue: "meforElement",
        collapsible: "collapsed",
        elementKind: "handler",
        elementName: h.name,
        open: opened(h),
        children: [
          ...refGroup(`${id}/fed`, "⇦ fed by", h.fed_by.map((r) => ref(`${id}/fed/${r}`, "router", r, "router"))),
          ...refGroup(`${id}/to`, "→ sends to", sendRefs(`${id}/to`, h.edges)),
          ...(h.dynamic ? [dynamicMarker(`${id}/dynamic`)] : []),
        ],
      };
    });

  const outbound = [...n.outbound.values()]
    .filter((o) => keep(o.name))
    .sort((a, b) => a.name.localeCompare(b.name))
    .map((o): VmNode => {
      const id = `el:outbound:${o.name}`;
      const receives = n.outboundReceives.get(o.name) ?? [];
      return {
        id,
        label: o.name,
        kind: "element",
        description: `${o.type}${shared(receives.length)}${runtimeSuffix(runtime?.get(runtimeKey("outbound", o.name)))}`,
        icon: "arrow-up",
        contextValue: "meforConnection",
        collapsible: "collapsed",
        elementKind: "outbound",
        elementName: o.name,
        open: opened(o),
        children: refGroup(
          `${id}/receives`,
          "⇦ receives from",
          receives.map((h) => ref(`${id}/receives/${h}`, "handler", h, "handler")),
        ),
      };
    });

  const sections = [
    section("sec:inbound", "Inbound Connections", inbound),
    section("sec:routers", "Routers", routers),
    section("sec:handlers", "Handlers", handlers),
    section("sec:outbound", "Outbound Connections", outbound),
  ];
  // While a filter is active only the matches matter — hide the sections it emptied (owner
  // feedback 2026-07-11: the lingering "0" section rows are noise around a filtered result).
  return f ? sections.filter((s) => s.children.length > 0) : sections;
}

// ---------------------------------------------------------------------------
// Flow perspective (the legacy chain, completed + badged)
// ---------------------------------------------------------------------------

function flowHandler(id: string, name: string, n: NormalGraph): VmNode {
  const h = n.handlers.get(name);
  const sends = h ? sendRefs(`${id}/send`, h.edges) : [];
  const children = [...sends, ...(h?.dynamic ? [dynamicMarker(`${id}/dynamic`)] : [])];
  return {
    id,
    label: name,
    kind: "element",
    description: `handler${shared(h?.fed_by.length ?? 0)}`,
    icon: "symbol-method",
    contextValue: "meforElement",
    collapsible: children.length ? "collapsed" : "none",
    children,
    elementKind: "handler",
    elementName: name,
    open: h ? opened(h) : undefined,
  };
}

function flowRouter(id: string, name: string, n: NormalGraph): VmNode {
  const r = n.routers.get(name);
  const handlerNames = r
    ? [...new Set(r.edges.filter((e) => e.target_kind === "handler").map((e) => e.target))].sort()
    : [];
  const children = [
    ...handlerNames.map((h) => flowHandler(`${id}/${h}`, h, n)),
    ...(r?.dynamic ? [dynamicMarker(`${id}/dynamic`)] : []),
  ];
  return {
    id,
    label: name,
    kind: "element",
    description: `router${shared(r?.fed_by.length ?? 0)}`,
    icon: "git-branch",
    contextValue: "meforElement",
    collapsible: children.length ? "collapsed" : "none",
    children,
    elementKind: "router",
    elementName: name,
    open: r ? opened(r) : undefined,
  };
}

export function buildFlowView(g: Graph, filter: string, grouping: GroupingMode): VmNode[] {
  const n = normalize(g);
  let conns: VmNode[] = [
    ...[...n.inbound.values()].map((c): VmNode => {
      const id = `flow:${c.name}`;
      return {
        id,
        label: c.name,
        kind: "element",
        description: `inbound · ${c.type}${port(c.settings)} → ${c.router}`,
        icon: "arrow-right",
        contextValue: "meforConnection",
        collapsible: "collapsed",
        children: [flowRouter(`${id}/${c.router}`, c.router, n)],
        elementKind: "inbound",
        elementName: c.name,
        open: opened(c),
      };
    }),
    ...[...n.outbound.values()].map((o): VmNode => {
      const receives = n.outboundReceives.get(o.name) ?? [];
      return {
        id: `flow:ob:${o.name}`,
        label: o.name,
        kind: "element",
        description: `outbound · ${o.type}${receives.length ? ` · ⇦ ${receives.length} handler(s)` : ""}`,
        icon: "arrow-up",
        contextValue: "meforConnection",
        collapsible: "none",
        children: [],
        elementKind: "outbound",
        elementName: o.name,
        open: opened(o),
      };
    }),
  ];
  const f = filter.trim().toLowerCase();
  if (f) {
    conns = conns.filter((c) => c.label.toLowerCase().includes(f));
  }
  conns.sort((a, b) => a.label.localeCompare(b.label));
  if (grouping === "none") {
    return conns;
  }
  const keyOf = grouping === "type" ? typeCode : partnerName;
  const groups = new Map<string, VmNode[]>();
  for (const c of conns) {
    const key = keyOf(c.label);
    const bucket = groups.get(key);
    if (bucket) {
      bucket.push(c);
    } else {
      groups.set(key, [c]);
    }
  }
  return [...groups.entries()]
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(
      ([key, children]): VmNode => ({
        id: `grp:${key}`,
        label: key,
        kind: "group",
        description: String(children.length),
        icon: "folder",
        collapsible: "expanded",
        children,
      }),
    );
}
